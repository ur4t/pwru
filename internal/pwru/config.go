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

var Config struct {
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

	// these are Config used internally, which means not configurable by users
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

func setConfig() {
	pflag.BoolVar(&Config.ShowVersion, "version", false, "show pwru version and exit")
	pflag.StringVar(&Config.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	pflag.StringSliceVar(&Config.KMods, "kmods", nil, "list of kernel modules names to attach to")
	pflag.BoolVar(&Config.AllKMods, "all-kmods", false, "attach to all available kernel modules")
	pflag.StringVar(&Config.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	pflag.StringVar(&Config.FilterProto, "filter-proto", "", "filter L4 protocol (tcp, udp, icmp, icmp6)")
	pflag.StringVar(&Config.FilterSrcIP, "filter-src-ip", "", "filter source IP addr")
	pflag.StringVar(&Config.FilterDstIP, "filter-dst-ip", "", "filter destination IP addr")
	pflag.Uint32Var(&Config.FilterNetns, "filter-netns", 0, "filter netns inode")
	pflag.Uint32Var(&Config.FilterMark, "filter-mark", 0, "filter skb mark")
	pflag.Uint16Var(&Config.FilterSrcPort, "filter-src-port", 0, "filter source port")
	pflag.Uint16Var(&Config.FilterDstPort, "filter-dst-port", 0, "filter destination port")
	pflag.Uint16Var(&Config.FilterPort, "filter-port", 0, "filter either destination or source port")
	pflag.StringVar(&Config.OutputTS, "timestamp", "none", "print timestamp per skb (\"current\", \"relative\", \"none\")")
	pflag.BoolVar(&Config.OutputMeta, "output-meta", false, "print skb metadata")
	pflag.BoolVar(&Config.OutputTuple, "output-tuple", false, "print L4 tuple")
	pflag.BoolVar(&Config.OutputSkb, "output-skb", false, "print skb")
	pflag.BoolVar(&Config.OutputStack, "output-stack", false, "print stack")
	pflag.Uint64Var(&Config.OutputLimitLines, "output-limit-lines", 0, "exit the program after the number of events has been received/printed")
	pflag.IntVar(&Config.PerCPUBuffer, "per-cpu-buffer", os.Getpagesize(), "per CPU buffer in bytes")

	pflag.StringVar(&Config.OutputFile, "output-file", "", "write traces to file")

	pflag.StringVar(&Config.ReadyFile, "ready-file", "", "create file after all BPF progs are attached")
	pflag.Lookup("ready-file").Hidden = true

	pflag.StringVar(&Config.Backend, "backend", "",
		fmt.Sprintf("Tracing backend('%s', '%s'). Will auto-detect if not specified.", BackendKprobe, BackendKprobeMulti))
}

func InitConfig() error {
	setConfig()
	pflag.Parse()

	var err error
	if Config.KernelBTF != "" {
		Config.BtfSpec, err = btf.LoadSpec(Config.KernelBTF)
	} else {
		Config.BtfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		return fmt.Errorf("failed to load BTF spec: %s", err)
	}

	if Config.AllKMods {
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			log.Fatalf("Failed to read directory: %s", err)
		}

		for _, file := range files {
			if !file.IsDir() && file.Name() != "vmlinux" {
				Config.KMods = append(Config.KMods, file.Name())
			}
		}
	}

	switch Config.Backend {
	case "":
	case BackendKprobe:
	case BackendKprobeMulti:
	default:
		return fmt.Errorf("invalid tracing backend %s", Config.Backend)
	}

	// Until https://lore.kernel.org/bpf/20221025134148.3300700-1-jolsa@kernel.org/
	// has been backported to the stable, kprobe-multi cannot be used when attaching
	// to kmods.
	if Config.Backend == "" && len(Config.KMods) == 0 {
		Config.UseKprobeMulti = HaveBPFLinkKprobeMulti()
	} else if Config.Backend == BackendKprobeMulti {
		Config.UseKprobeMulti = true
	}

	return nil
}

func ConfigBPFMap(cfgMap *ebpf.Map) {
	cfg := FilterCfg{
		FilterNetns: Config.FilterNetns,
		FilterMark:  Config.FilterMark,
	}
	if Config.FilterPort > 0 {
		cfg.FilterPort = byteorder.HostToNetwork16(Config.FilterPort)
	} else {
		if Config.FilterSrcPort > 0 {
			cfg.FilterSrcPort = byteorder.HostToNetwork16(Config.FilterSrcPort)
		}
		if Config.FilterDstPort > 0 {
			cfg.FilterDstPort = byteorder.HostToNetwork16(Config.FilterDstPort)
		}
	}
	if Config.OutputSkb {
		cfg.OutputSkb = 1
	}
	if Config.OutputMeta {
		cfg.OutputMeta = 1
	}
	if Config.OutputTuple {
		cfg.OutputTuple = 1
	}
	if Config.OutputStack {
		cfg.OutputStack = 1
	}

	switch strings.ToLower(Config.FilterProto) {
	case "tcp":
		cfg.FilterProto = syscall.IPPROTO_TCP
	case "udp":
		cfg.FilterProto = syscall.IPPROTO_UDP
	case "icmp":
		cfg.FilterProto = syscall.IPPROTO_ICMP
	case "icmp6":
		cfg.FilterProto = syscall.IPPROTO_ICMPV6
	}

	if Config.FilterDstIP != "" {
		ip := net.ParseIP(Config.FilterDstIP)
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

	if Config.FilterSrcIP != "" {
		ip := net.ParseIP(Config.FilterSrcIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-src-ip")
		}

		versionMatch := true
		if ip4 := ip.To4(); ip4 == nil {
			if cfg.FilterIPv6 <= 0 && Config.FilterDstIP != "" {
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
