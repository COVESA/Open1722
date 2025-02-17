package utils

import (
	"flag"
	"net/netip"
)

func ParseFlags() (*Flags, error) {
	var f Flags

	flag.StringVar(&f._DstIP, "dest-ip", "127.0.0.1", "Destination IP")
	flag.StringVar(&f._SrcIP, "src-ip", "127.0.0.1", "Source IP")
	flag.UintVar(&f.SrcPort, "src-port", 0, "Source Port")
	flag.UintVar(&f.DstPort, "dst-port", 0, "Destination Port")

	flag.UintVar(&f.PidSender, "pid-sender", 0, "pid to filter")
	flag.UintVar(&f.PidReceiver, "pid-receiver", 0, "pid to filter")

	flag.Parse()

	if f._DstIP != "" {
		addr, err := netip.ParseAddr(f._DstIP)
		if err != nil {
			return nil, err
		}
		f.DstIP = addr
	}
	if f._SrcIP != "" {
		addr, err := netip.ParseAddr(f._SrcIP)
		if err != nil {
			return nil, err
		}
		f.SrcIP = addr
	}

	return &f, nil
}

func (f *Flags) GetConfig() *Config {
	var c Config
	c.PidSender = uint32(f.PidSender)
	c.PidReceiver = uint32(f.PidReceiver)
	c.SrcIP = f.SrcIP.As4()
	c.DstIP = f.DstIP.As4()
	c.SrcPort = uint32(f.SrcPort)
	c.DstPort = uint32(f.DstPort)
	return &c
}
