// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package pwru

import (
	"github.com/cilium/ebpf"
)

const (
	MaxStackDepth = 50

	BackendKprobe      = "kprobe"
	BackendKprobeMulti = "kprobe-multi"
)

type Tuple struct {
	Saddr   [16]byte
	Daddr   [16]byte
	Sport   uint16
	Dport   uint16
	L3Proto uint16
	L4Proto uint8
	Pad     uint8
}

type Meta struct {
	Netns   uint32
	Mark    uint32
	Ifindex uint32
	Len     uint32
	MTU     uint32
	Proto   uint16
	Pad     uint16
}

type StackData struct {
	IPs [MaxStackDepth]uint64
}

type Event struct {
	PID          uint32
	Type         uint32
	Addr         uint64
	SAddr        uint64
	Timestamp    uint64
	PrintSkbId   uint64
	Meta         Meta
	Tuple        Tuple
	PrintStackId int64
	CPU          uint32
}

type KProbeMaps interface {
	GetCfgMap() *ebpf.Map
	GetEvents() *ebpf.Map
	GetPrintStackMap() *ebpf.Map
}

type KProbeMapsWithOutputSKB interface {
	KProbeMaps
	GetPrintSkbMap() *ebpf.Map
}

type KProbePrograms interface {
	GetKprobeSkb1() *ebpf.Program
	GetKprobeSkb2() *ebpf.Program
	GetKprobeSkb3() *ebpf.Program
	GetKprobeSkb4() *ebpf.Program
	GetKprobeSkb5() *ebpf.Program
}

type KProbeObjects interface {
	KProbeMaps
	KProbePrograms
	Close() error
}
