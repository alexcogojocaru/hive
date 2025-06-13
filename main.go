package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux xdp bpf/ratelimit.c

const InterfaceName = "enp0s31f6"

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v\n", err)
	}

	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load xdp objects: %v\n", err)
	}

	iface, err := net.InterfaceByName(InterfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v\n", InterfaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Program:   objs.Ratelimit,
	})
	if err != nil {
		log.Fatalf("Failed to attach xdp program to interface %s: %v\n", InterfaceName, err)
	}
	defer l.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Waiting for stop signal...")
	<-stop
}
