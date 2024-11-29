package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type ArpEvent struct {
	SrcMac [6]byte
	DstMac [6]byte
	SrcIP  [4]byte
	DstIP  [4]byte
	Op     uint16 // ARP opcode: request (1) or reply (2)
}

func setMemlockLimit() error {
	var rlimit unix.Rlimit
	rlimit.Cur = unix.RLIM_INFINITY
	rlimit.Max = unix.RLIM_INFINITY
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		return err
	}
	return nil
}

func main() {
	// Set memory lock limit
	if err := setMemlockLimit(); err != nil {
		log.Fatalf("Failed to set MEMLOCK limit: %v", err)
	}

	logger := log.New(os.Stdout, "ARPAgent: ", log.LstdFlags)

	logger.Println("Starting ARP packet capture...")

	// Load pre-compiled eBPF object file
	spec, err := ebpf.LoadCollectionSpec("arp_capture.o")
	if err != nil {
		logger.Fatalf("Error loading eBPF object file: %v", err)
	}

	// Load the eBPF program
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		logger.Fatalf("Error creating eBPF collection: %v", err)
	}
	defer coll.Close()

	// Get the network interface
	iface, err := net.InterfaceByName("enp0s8") // Replace with your interface name
	if err != nil {
		logger.Fatalf("Error getting interface: %v", err)
	}

	// Attach the eBPF program
	logger.Printf("Attaching eBPF program to interface %s (index %d)...", iface.Name, iface.Index)
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["capture_arp"],
		Interface: iface.Index,
	})
	if err != nil {
		logger.Fatalf("Error attaching eBPF program: %v", err)
	}
	defer xdpLink.Close()

	logger.Println("eBPF program attached successfully.")

	// Set up perf event reader
	reader, err := perf.NewReader(coll.Maps["events"], 4096)
	if err != nil {
		logger.Fatalf("Error creating perf reader: %v", err)
	}
	defer reader.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	macaddrs := make(map[string]interface{})
	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				logger.Printf("Error reading perf event: %v", err)
				continue
			}

			// Parse ARP event
			var event ArpEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				logger.Printf("Error parsing ARP event: %v", err)
				continue
			}

			// Log ARP details

			srcmac := net.HardwareAddr(event.SrcMac[:])
			srcip := net.IP(event.SrcIP[:])
			dstmac := net.HardwareAddr(event.DstMac[:])
			dstip := net.IP(event.DstIP[:])

			// Add the Mac addresses discovered from the filter.
			macaddrs[srcmac.String()] = srcip.String()
			// If the response if an Arp reply also get the Mac if present.
			if dstmac.String() != "00:00:00:00:00:00" {
				macaddrs[dstmac.String()] = dstip.String()
			}
			logger.Printf("ARP Packet Captured (Op: %d):", event.Op)
			logger.Printf("  Updated Mac Map: %s", macaddrs)
			// logger.Printf("  Source MAC: %s", srcmac)
			// logger.Printf("  Source IP: %s", srcip)
			// logger.Printf("  Target MAC: %s", dstmac)
			// logger.Printf("  Target IP: %s\n", dstip)
		}
	}()

	logger.Println("Listening for ARP packets using eBPF...")
	<-sigChan
	logger.Println("Exiting ARP packet capture.")
}
