// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	ps "github.com/mitchellh/go-ps"

	"github.com/cilium/pwru/internal/byteorder"
)

type output struct {
	lastSeenSkb   map[uint64]uint64 // skb addr => last seen TS
	printSkbMap   *ebpf.Map
	printStackMap *ebpf.Map
	writer        io.Writer
	kprobeMulti   bool
}

func NewOutput(printSkbMap *ebpf.Map, printStackMap *ebpf.Map, kprobeMulti bool) (*output, error) {
	writer := os.Stdout

	if Flags.OutputFile != "" {
		file, err := os.Create(Flags.OutputFile)
		if err != nil {
			return nil, err
		}
		writer = file
	}

	return &output{
		lastSeenSkb:   map[uint64]uint64{},
		printSkbMap:   printSkbMap,
		printStackMap: printStackMap,
		writer:        writer,
		kprobeMulti:   kprobeMulti,
	}, nil
}

func (o *output) PrintHeader() {
	fmt.Fprintf(o.writer, "%18s %6s %16s %24s", "SKB", "CPU", "PROCESS", "FUNC")
	if Flags.OutputTS != "none" {
		fmt.Fprintf(o.writer, " %16s", "TIMESTAMP")
	}
	fmt.Fprintf(o.writer, "\n")
}

func (o *output) Print(event *Event) {
	p, err := ps.FindProcess(int(event.PID))
	execName := "<empty>"
	if err == nil && p != nil {
		execName = p.Executable()
	}
	ts := event.Timestamp
	if Flags.OutputTS == "relative" {
		if last, found := o.lastSeenSkb[event.SAddr]; found {
			ts = ts - last
		} else {
			ts = 0
		}
	}
	var addr uint64
	// XXX: not sure why the -1 offset is needed on x86 but not on arm64
	switch runtime.GOARCH {
	case "amd64":
		addr = event.Addr
		if !o.kprobeMulti {
			addr -= 1
		}
	case "arm64":
		addr = event.Addr
	}
	var funcName string
	if name, ok := ksymAddr2Name[addr]; ok {
		funcName = name
	} else if ksym, ok := ksymAddr2Name[addr-4]; runtime.GOARCH == "amd64" && ok {
		// Assume that function has ENDBR in its prelude (enabled by CONFIG_X86_KERNEL_IBT).
		// See https://lore.kernel.org/bpf/20220811091526.172610-5-jolsa@kernel.org/
		// for more ctx.
		funcName = ksym
	} else {
		funcName = fmt.Sprintf("0x%x", addr)
	}
	fmt.Fprintf(o.writer, "%18s %6s %16s %24s", fmt.Sprintf("0x%x", event.SAddr),
		fmt.Sprintf("%d", event.CPU), fmt.Sprintf("[%s]", execName), funcName)
	if Flags.OutputTS != "none" {
		fmt.Fprintf(o.writer, " %16d", ts)
	}
	o.lastSeenSkb[event.SAddr] = event.Timestamp

	if Flags.OutputMeta {
		fmt.Fprintf(o.writer, " netns=%d mark=0x%x ifindex=%d proto=%x mtu=%d len=%d", event.Meta.Netns, event.Meta.Mark, event.Meta.Ifindex, event.Meta.Proto, event.Meta.MTU, event.Meta.Len)
	}

	if Flags.OutputTuple {
		fmt.Fprintf(o.writer, " %s:%d->%s:%d(%s)",
			addrToStr(event.Tuple.L3Proto, event.Tuple.Saddr), byteorder.NetworkToHost16(event.Tuple.Sport),
			addrToStr(event.Tuple.L3Proto, event.Tuple.Daddr), byteorder.NetworkToHost16(event.Tuple.Dport),
			protoToStr(event.Tuple.L4Proto))
	}

	if Flags.OutputStack && event.PrintStackId > 0 {
		var stack StackData
		id := uint32(event.PrintStackId)
		if err := o.printStackMap.Lookup(&id, &stack); err == nil {
			for _, ip := range stack.IPs {
				if ip > 0 {
					fmt.Fprintf(o.writer, "\n%s", findNearestSym(ip))
				}
			}
		}
		_ = o.printStackMap.Delete(&id)
	}

	if Flags.OutputSkb {
		id := uint32(event.PrintSkbId)
		if str, err := o.printSkbMap.LookupBytes(&id); err == nil {
			fmt.Fprintf(o.writer, "\n%s", string(str))
		}
	}

	fmt.Fprintln(o.writer)
}

func protoToStr(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	case syscall.IPPROTO_ICMPV6:
		return "icmp6"
	default:
		return ""
	}
}

func addrToStr(proto uint16, addr [16]byte) string {
	switch proto {
	case syscall.ETH_P_IP:
		return net.IP(addr[:4]).String()
	case syscall.ETH_P_IPV6:
		return fmt.Sprintf("[%s]", net.IP(addr[:]).String())
	default:
		return ""
	}
}
