// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package pwru

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/pwru/internal/byteorder"
	"github.com/spf13/pflag"
)

// Version is the pwru version and is set at compile time via LDFLAGS-
var Version string = "version unknown"

var Flags struct {
	ShowVersion bool

	KernelBTF string

	FilterNetns   uint32
	FilterMark    uint32
	FilterFunc    string
	FilterProto   string
	FilterSrcIP   string
	FilterDstIP   string
	FilterSrcPort uint16
	FilterDstPort uint16
	FilterPort    uint16

	OutputTS         string
	OutputMeta       bool
	OutputTuple      bool
	OutputSkb        bool
	OutputStack      bool
	OutputLimitLines uint64
	OutputFile       string

	PerCPUBuffer int
	KMods        []string
	AllKMods     bool

	ReadyFile string

	Backend string

	// these are flags used internally, which means not configurable by users
	UseKprobeMulti bool
	BtfSpec        *btf.Spec
}

type FilterCfg struct {
	FilterNetns uint32
	FilterMark  uint32

	//Filter l3
	FilterIPv6  uint8
	FilterSrcIP [16]byte
	FilterDstIP [16]byte

	//Filter l4
	FilterProto   uint8
	FilterSrcPort uint16
	FilterDstPort uint16
	FilterPort    uint16

	//TODO: if there are more options later, then you can consider using a bit map
	OutputRelativeTS uint8
	OutputMeta       uint8
	OutputTuple      uint8
	OutputSkb        uint8
	OutputStack      uint8

	Pad byte
}

func SetFlags() {
	pflag.BoolVar(&Flags.ShowVersion, "version", false, "show pwru version and exit")
	pflag.StringVar(&Flags.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	pflag.StringSliceVar(&Flags.KMods, "kmods", nil, "list of kernel modules names to attach to")
	pflag.BoolVar(&Flags.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	pflag.StringVar(&Flags.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	pflag.StringVar(&Flags.FilterProto, "filter-proto", "", "filter L4 protocol (tcp, udp, icmp, icmp6)")
	pflag.StringVar(&Flags.FilterSrcIP, "filter-src-ip", "", "filter source IP addr")
	pflag.StringVar(&Flags.FilterDstIP, "filter-dst-ip", "", "filter destination IP addr")
	pflag.Uint32Var(&Flags.FilterNetns, "filter-netns", 0, "filter netns inode")
	pflag.Uint32Var(&Flags.FilterMark, "filter-mark", 0, "filter skb mark")
	pflag.Uint16Var(&Flags.FilterSrcPort, "filter-src-port", 0, "filter source port")
	pflag.Uint16Var(&Flags.FilterDstPort, "filter-dst-port", 0, "filter destination port")
	pflag.Uint16Var(&Flags.FilterPort, "filter-port", 0, "filter either destination or source port")
	pflag.StringVar(&Flags.OutputTS, "timestamp", "none", "print timestamp per skb (\"current\", \"relative\", \"none\")")
	pflag.BoolVar(&Flags.OutputMeta, "output-meta", false, "print skb metadata")
	pflag.BoolVar(&Flags.OutputTuple, "output-tuple", false, "print L4 tuple")
	pflag.BoolVar(&Flags.OutputSkb, "output-skb", false, "print skb")
	pflag.BoolVar(&Flags.OutputStack, "output-stack", false, "print stack")
	pflag.Uint64Var(&Flags.OutputLimitLines, "output-limit-lines", 0, "exit the program after the number of events has been received/printed")
	pflag.IntVar(&Flags.PerCPUBuffer, "per-cpu-buffer", os.Getpagesize(), "per CPU buffer in bytes")

	pflag.StringVar(&Flags.OutputFile, "output-file", "", "write traces to file")

	pflag.StringVar(&Flags.ReadyFile, "ready-file", "", "create file after all BPF progs are attached")
	pflag.Lookup("ready-file").Hidden = true

	pflag.StringVar(&Flags.Backend, "backend", "",
		fmt.Sprintf("Tracing backend('%s', '%s'). Will auto-detect if not specified.", BackendKprobe, BackendKprobeMulti))
}

func ConfigBPFMap(cfgMap *ebpf.Map) {
	cfg := FilterCfg{
		FilterNetns: Flags.FilterNetns,
		FilterMark:  Flags.FilterMark,
	}
	if Flags.FilterPort > 0 {
		cfg.FilterPort = byteorder.HostToNetwork16(Flags.FilterPort)
	} else {
		if Flags.FilterSrcPort > 0 {
			cfg.FilterSrcPort = byteorder.HostToNetwork16(Flags.FilterSrcPort)
		}
		if Flags.FilterDstPort > 0 {
			cfg.FilterDstPort = byteorder.HostToNetwork16(Flags.FilterDstPort)
		}
	}
	if Flags.OutputSkb {
		cfg.OutputSkb = 1
	}
	if Flags.OutputMeta {
		cfg.OutputMeta = 1
	}
	if Flags.OutputTuple {
		cfg.OutputTuple = 1
	}
	if Flags.OutputStack {
		cfg.OutputStack = 1
	}

	switch strings.ToLower(Flags.FilterProto) {
	case "tcp":
		cfg.FilterProto = syscall.IPPROTO_TCP
	case "udp":
		cfg.FilterProto = syscall.IPPROTO_UDP
	case "icmp":
		cfg.FilterProto = syscall.IPPROTO_ICMP
	case "icmp6":
		cfg.FilterProto = syscall.IPPROTO_ICMPV6
	}

	if Flags.FilterDstIP != "" {
		ip := net.ParseIP(Flags.FilterDstIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-dst-ip")
		}
		if ip4 := ip.To4(); ip4 == nil {
			cfg.FilterIPv6 = 1
			copy(cfg.FilterDstIP[:], ip.To16()[:])
		} else {
			copy(cfg.FilterDstIP[:], ip4[:])
		}
	}

	if Flags.FilterSrcIP != "" {
		ip := net.ParseIP(Flags.FilterSrcIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-src-ip")
		}

		versionMatch := true
		if ip4 := ip.To4(); ip4 == nil {
			if cfg.FilterIPv6 <= 0 && Flags.FilterDstIP != "" {
				versionMatch = false
			}
			copy(cfg.FilterSrcIP[:], ip.To16()[:])
		} else {
			if cfg.FilterIPv6 > 0 {
				versionMatch = false
			}
			copy(cfg.FilterSrcIP[:], ip4[:])
		}
		if !versionMatch {
			log.Fatalf("filter-src-ip and filter-dst-ip should have same version.")
		}
	}

	if err := cfgMap.Update(uint32(0), cfg, 0); err != nil {
		log.Fatalf("Failed to set filter map: %v", err)
	}
}
