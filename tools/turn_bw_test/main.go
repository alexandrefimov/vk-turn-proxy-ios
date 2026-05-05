// turn_bw_test — measures TURN allocation throughput against a VK relay.
//
// Two modes:
//   - Single allocation (default, -parallel=1): one TURN allocation, one
//     long-running send loop, prints rate every 2s and final summary.
//   - Parallel allocations (-parallel=N): spawns N independent allocations
//     using slots 0..N-1 from the backup, each with its own TURN client
//     and its own send loop, all writing to the same destination. Used
//     to detect VK shaping that triggers on parallel-allocation patterns
//     (single allocation may slip under the radar; many parallel may
//     trip an aggregate cap or per-conn throttle).
//
// Required setup:
//   1. On the VPS, run:    nc -u -k -l 9999 | pv -W -b -r -t > /dev/null
//      (counts received bytes, prints accumulated total + rate)
//   2. Disconnect the iOS VPN app — its 50 active conns hold quota
//      against these creds.
//   3. Export a backup from iOS Settings → Backup & Restore → Export Full
//      Backup. The JSON contains valid creds for each slot we'll use.
//   4. Move the backup file to the Mac.
//
// Usage:
//   # Single allocation (baseline):
//   go run ./tools/turn_bw_test -creds=backup.json -slot=0 \
//       -dst-ip=217.168.246.242 -dst-port=9999 \
//       -transport=tcp -duration=30s
//
//   # Parallel allocations (find shaping threshold):
//   go run ./tools/turn_bw_test -creds=backup.json -parallel=5 \
//       -dst-ip=217.168.246.242 -dst-port=9999 \
//       -transport=udp -duration=30s
//   (slot=0 ignored when parallel>1; uses slots 0..parallel-1)

package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

type backupCred struct {
	Address    string `json:"address"`
	LastUsedAt int64  `json:"last_used_at"`
	Password   string `json:"password"`
	Slot       int    `json:"slot"`
	Username   string `json:"username"`
}

type backupFile struct {
	TurnPool struct {
		Creds []backupCred `json:"creds"`
	} `json:"turn_pool"`
}

// workerStats holds per-conn live counters used by the aggregate printer
// and end-of-test summary.
type workerStats struct {
	slot      int
	bytesSent atomic.Int64
	pktsSent  atomic.Int64
	sendErrs  atomic.Int64
	lastErr   atomic.Value // error
	allocOK   atomic.Bool
	allocDur  time.Duration
	relayed   string
	startTime time.Time
}

func main() {
	credsPath := flag.String("creds", "", "path to backup JSON exported from iOS app")
	slot := flag.Int("slot", 0, "single-mode: which slot's cred to use (ignored if -parallel > 1)")
	parallel := flag.Int("parallel", 1, "number of parallel allocations (uses slots 0..N-1)")
	dstIP := flag.String("dst-ip", "217.168.246.242", "destination IP (your VPS)")
	dstPort := flag.Int("dst-port", 9999, "destination UDP port on the VPS")
	transport := flag.String("transport", "udp", "udp or tcp")
	duration := flag.Duration("duration", 30*time.Second, "test duration")
	pktSize := flag.Int("pkt-size", 1280, "send-payload size, bytes")
	verbose := flag.Bool("v", false, "verbose pion logging")
	tcpAllocation := flag.Bool("tcp-allocation", false,
		"use RFC 6062 TCP allocation (relay↔peer also TCP, not UDP). "+
			"VPS must have TCP listener on -dst-port instead of UDP. "+
			"Forces -transport=tcp.")
	flag.Parse()

	if *credsPath == "" {
		log.Fatal("missing -creds <path>")
	}
	if *tcpAllocation {
		// TCP allocation requires the control connection to be TCP too —
		// it's a TCP-end-to-end mode. Force the transport.
		if *transport != "tcp" {
			fmt.Printf("note: -tcp-allocation forces -transport=tcp (was %s)\n", *transport)
			*transport = "tcp"
		}
	}
	if *transport != "udp" && *transport != "tcp" {
		log.Fatalf("transport must be udp or tcp, got %q", *transport)
	}
	if *parallel < 1 {
		log.Fatal("-parallel must be >= 1")
	}

	// Pre-load all creds we'll need, fail fast if any slot missing.
	var creds []*backupCred
	if *parallel == 1 {
		c, err := loadCred(*credsPath, *slot)
		if err != nil {
			log.Fatalf("load creds: %v", err)
		}
		creds = []*backupCred{c}
	} else {
		for i := 0; i < *parallel; i++ {
			c, err := loadCred(*credsPath, i)
			if err != nil {
				log.Fatalf("need slot %d for parallel=%d: %v", i, *parallel, err)
			}
			creds = append(creds, c)
		}
	}

	dstAddr := &net.UDPAddr{IP: net.ParseIP(*dstIP), Port: *dstPort}

	fmt.Printf("=== TURN bandwidth test ===\n")
	fmt.Printf("Transport:    %s\n", *transport)
	fmt.Printf("Parallel:     %d allocation(s) (slots %v)\n", *parallel, slotsOf(creds))
	fmt.Printf("TURN relay:   %s\n", creds[0].Address)
	fmt.Printf("Destination:  %s\n", dstAddr)
	fmt.Printf("Duration:     %s, payload: %d bytes\n\n", *duration, *pktSize)

	loggerFactory := logging.NewDefaultLoggerFactory()
	if *verbose {
		loggerFactory.DefaultLogLevel = logging.LogLevelDebug
	} else {
		loggerFactory.DefaultLogLevel = logging.LogLevelWarn
	}

	// Spawn N workers, run them concurrently, aggregate live + final.
	stats := make([]*workerStats, len(creds))
	for i := range creds {
		stats[i] = &workerStats{slot: creds[i].Slot}
	}
	var wg sync.WaitGroup
	startBarrier := make(chan struct{}) // released once all workers have allocated
	allocReady := make(chan int, len(creds))

	for i, c := range creds {
		wg.Add(1)
		go func(idx int, cred *backupCred) {
			defer wg.Done()
			runWorker(idx, cred, dstAddr, *transport, *tcpAllocation, *pktSize, *duration,
				loggerFactory, stats[idx], allocReady, startBarrier)
		}(i, c)
	}

	// Wait for all allocations or fail-fast on any error.
	allocCount := 0
	allocStart := time.Now()
	for allocCount < len(creds) {
		select {
		case idx := <-allocReady:
			allocCount++
			s := stats[idx]
			if s.allocOK.Load() {
				fmt.Printf("[slot %d] Allocate OK in %s, relayed %s\n",
					s.slot, s.allocDur.Round(time.Millisecond), s.relayed)
			} else {
				fmt.Printf("[slot %d] Allocate FAILED — see worker error\n", s.slot)
			}
		case <-time.After(30 * time.Second):
			fmt.Printf("!! timeout waiting for all allocations after %s; only %d/%d ready\n",
				time.Since(allocStart).Round(time.Millisecond), allocCount, len(creds))
			os.Exit(1)
		}
	}
	fmt.Printf("All %d allocations ready in %s, releasing send barrier\n\n",
		len(creds), time.Since(allocStart).Round(time.Millisecond))
	close(startBarrier)

	// Aggregate live tick — every 2s print per-conn + total rate.
	doneCh := make(chan struct{})
	go aggregatePrinter(stats, doneCh)

	wg.Wait()
	close(doneCh)
	time.Sleep(100 * time.Millisecond) // let last printer line flush

	// Final summary.
	fmt.Printf("\n=== RESULT (transport=%s, parallel=%d) ===\n", *transport, len(creds))
	var totalBytes int64
	var totalPkts int64
	var totalErrs int64
	var maxElapsed time.Duration
	for _, s := range stats {
		bs := s.bytesSent.Load()
		pk := s.pktsSent.Load()
		er := s.sendErrs.Load()
		totalBytes += bs
		totalPkts += pk
		totalErrs += er
		dur := time.Since(s.startTime)
		if dur > maxElapsed {
			maxElapsed = dur
		}
		bps := float64(bs) * 8 / dur.Seconds()
		fmt.Printf("  slot %d: %s sent (%d pkts, %d errs) in %s = %s\n",
			s.slot, humanBytes(bs), pk, er, dur.Round(10*time.Millisecond),
			humanRate(bps))
	}
	totalBps := float64(totalBytes) * 8 / maxElapsed.Seconds()
	fmt.Printf("  ---\n")
	fmt.Printf("  TOTAL:  %s sent (%d pkts, %d errs) over ~%s = %s\n",
		humanBytes(totalBytes), totalPkts, totalErrs,
		maxElapsed.Round(10*time.Millisecond), humanRate(totalBps))
	fmt.Printf("\nNote: client-side rate is what the kernel buffered; the\n")
	fmt.Printf("      true network throughput is what your VPS pv showed.\n")
	fmt.Printf("      Compare both numbers — for UDP they often diverge.\n")
}

// runWorker handles one allocation's full lifecycle: connect, allocate,
// signal ready, wait for barrier, send for duration, log into stats.
func runWorker(idx int, cred *backupCred, dstAddr *net.UDPAddr,
	transport string, tcpAllocation bool, pktSize int, duration time.Duration,
	loggerFactory *logging.DefaultLoggerFactory, stats *workerStats,
	allocReady chan<- int, startBarrier <-chan struct{},
) {
	turnAddr := cred.Address

	// Build the connection that pion/turn runs over.
	var conn net.PacketConn
	switch transport {
	case "udp":
		// Explicitly udp4 — net.ListenPacket("udp", ...) creates a dual-
		// stack socket whose LocalAddr appears as [::]:port (IPv6
		// representation), and pion auto-infers an IPv6 allocation
		// which VK silently drops.
		c, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			fmt.Printf("[slot %d] listen udp: %v\n", cred.Slot, err)
			allocReady <- idx
			return
		}
		conn = c
	case "tcp":
		dialer := net.Dialer{Timeout: 5 * time.Second}
		tcp, err := dialer.Dial("tcp", turnAddr)
		if err != nil {
			fmt.Printf("[slot %d] dial tcp: %v\n", cred.Slot, err)
			allocReady <- idx
			return
		}
		conn = turn.NewSTUNConn(tcp)
	}
	defer conn.Close()

	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   conn,
		Username:               cred.Username,
		Password:               cred.Password,
		Realm:                  "okcdn.ru",
		Software:               "vk-turn-bw-test",
		LoggerFactory:          loggerFactory,
		RequestedAddressFamily: turn.RequestedAddressFamilyIPv4,
	}
	client, err := turn.NewClient(cfg)
	if err != nil {
		fmt.Printf("[slot %d] turn.NewClient: %v\n", cred.Slot, err)
		allocReady <- idx
		return
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		fmt.Printf("[slot %d] client.Listen: %v\n", cred.Slot, err)
		allocReady <- idx
		return
	}

	allocStart := time.Now()

	// Two allocation modes:
	//   - Standard (Allocate): UDP allocation. relayConn is a
	//     net.PacketConn; we WriteTo(dstAddr) per packet, relay forwards
	//     to peer via UDP. This is the default and what RFC 5766 covers.
	//   - TCP allocation (AllocateTCP, RFC 6062): relay opens a TCP
	//     connection to the peer (instead of UDP). The actual data flow
	//     uses a SECOND TCP connection from us to the relay, opened via
	//     alloc.Dial("tcp", peerAddr) — that returns a net.Conn that
	//     bidirectionally forwards bytes to the peer over TCP at both
	//     legs (us↔relay TCP, relay↔peer TCP). End-to-end TCP path,
	//     no UDP shaper applies anywhere.
	var sendFn func(payload []byte) (int, error)
	var sendCloser io.Closer

	if tcpAllocation {
		alloc, err := client.AllocateTCP()
		if err != nil {
			fmt.Printf("[slot %d] AllocateTCP: %v\n", cred.Slot, err)
			allocReady <- idx
			return
		}
		defer alloc.Close()

		// Dial through this allocation to the peer. Internally pion
		// sends a CONNECT request to the relay, gets a ConnectionID,
		// opens a separate TCP conn to the relay, and BindConnection
		// to that ID — RFC 6062 dance.
		dstStr := dstAddr.String()
		// alloc.Dial expects "tcp" / "tcp4" / "tcp6"; using "tcp"
		// matches the default IPv4 server.
		dataConn, err := alloc.Dial("tcp", dstStr)
		if err != nil {
			fmt.Printf("[slot %d] alloc.Dial(%s): %v\n", cred.Slot, dstStr, err)
			allocReady <- idx
			return
		}
		sendCloser = dataConn
		sendFn = func(payload []byte) (int, error) {
			return dataConn.Write(payload)
		}
		stats.relayed = alloc.Addr().String()
	} else {
		relayConn, err := client.Allocate()
		if err != nil {
			fmt.Printf("[slot %d] Allocate: %v\n", cred.Slot, err)
			allocReady <- idx
			return
		}
		sendCloser = relayConn
		sendFn = func(payload []byte) (int, error) {
			return relayConn.WriteTo(payload, dstAddr)
		}
		stats.relayed = relayConn.LocalAddr().String()
		// Drain reads in background — pion's UDP relay conn surfaces
		// refresh / binding messages. For TCP allocations the dataConn
		// is a separate stream (the control allocation handles its own
		// refreshes internally) so we don't drain there.
		doneCh := make(chan struct{})
		defer close(doneCh)
		go func() {
			buf := make([]byte, 64*1024)
			for {
				select {
				case <-doneCh:
					return
				default:
				}
				_ = relayConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				_, _, err := relayConn.ReadFrom(buf)
				if err != nil {
					if isTimeout(err) || err == io.EOF {
						continue
					}
					return
				}
			}
		}()
	}
	defer sendCloser.Close()

	stats.allocDur = time.Since(allocStart)
	stats.allocOK.Store(true)
	allocReady <- idx

	// Wait for all workers to finish allocating before sending starts —
	// gives a clean comparison window where everyone is sending in the
	// same time slice.
	<-startBarrier

	payload := make([]byte, pktSize)
	if _, err := rand.Read(payload); err != nil {
		fmt.Printf("[slot %d] rand: %v\n", cred.Slot, err)
		return
	}

	stats.startTime = time.Now()
	deadline := stats.startTime.Add(duration)

	for time.Now().Before(deadline) {
		n, err := sendFn(payload)
		if err != nil {
			stats.sendErrs.Add(1)
			stats.lastErr.Store(err)
			if stats.sendErrs.Load() > 100 {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		stats.bytesSent.Add(int64(n))
		stats.pktsSent.Add(1)
	}
}

// aggregatePrinter ticks every 2s and prints per-slot + total rate.
func aggregatePrinter(stats []*workerStats, doneCh <-chan struct{}) {
	type snap struct {
		t     time.Time
		bytes int64
	}
	prev := make([]snap, len(stats))
	for i, s := range stats {
		prev[i] = snap{t: time.Now(), bytes: s.bytesSent.Load()}
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-doneCh:
			return
		case t := <-ticker.C:
			parts := []string{}
			var total int64
			for i, s := range stats {
				cur := s.bytesSent.Load()
				dt := t.Sub(prev[i].t).Seconds()
				if dt <= 0 {
					dt = 1
				}
				rate := float64(cur-prev[i].bytes) * 8 / dt
				total += cur - prev[i].bytes
				parts = append(parts, fmt.Sprintf("[s%d]%s",
					s.slot, humanRate(rate)))
				prev[i] = snap{t: t, bytes: cur}
			}
			totalRate := float64(total) * 8 / 2.0
			fmt.Printf("  %s   %s   TOTAL=%s\n",
				time.Now().Format("15:04:05"),
				strings.Join(parts, "  "),
				humanRate(totalRate))
		}
	}
}

func loadCred(path string, slot int) (*backupCred, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bf backupFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("parse backup JSON: %w", err)
	}
	for i := range bf.TurnPool.Creds {
		c := &bf.TurnPool.Creds[i]
		if c.Slot == slot {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no cred for slot %d in %s", slot, path)
}

func slotsOf(creds []*backupCred) []int {
	out := make([]int, len(creds))
	for i, c := range creds {
		out[i] = c.Slot
	}
	return out
}

func humanBytes(b int64) string {
	const k = 1024.0
	switch {
	case float64(b) >= k*k*k:
		return fmt.Sprintf("%.2f GiB", float64(b)/k/k/k)
	case float64(b) >= k*k:
		return fmt.Sprintf("%.2f MiB", float64(b)/k/k)
	case float64(b) >= k:
		return fmt.Sprintf("%.1f KiB", float64(b)/k)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// humanRate formats bits-per-second adaptively. Single-conn UDP write
// rate easily hits Gbps so don't pin to a single unit.
func humanRate(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1f kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if t, ok := err.(interface{ Timeout() bool }); ok && t.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded")
}
