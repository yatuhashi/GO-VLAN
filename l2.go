package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 100 * time.Millisecond
	handle       *pcap.Handle
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		fmt.Println("Name: ", device.Name)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
		}
	}
	var CapDevice string
	fmt.Print("Input Interface Name : ")
	fmt.Scan(&CapDevice)
	// Open device
	if handle, err = pcap.OpenLive(CapDevice, snapshot_len, promiscuous, timeout); err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		layer2 := packet.Layers()[1]
		fmt.Println("[", layer2.LayerType(), " : ", layer2.LayerContents()[1], "]")
	}
}
