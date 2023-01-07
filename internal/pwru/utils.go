// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

var funcs = make(map[string]int)

// Currently libbpf only support getting first 5 params
const maxParamPos = 5

// getAvailableFilterFunctions return list of functions to which it is possible
// to attach kprobes.
func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

func InitFuncs() error {
	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	reg, err := regexp.Compile(Flags.FilterFunc)
	if err != nil {
		return fmt.Errorf("failed to compile regular expression %v", err)
	}

	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	iters := []iterator{{"", Flags.BtfSpec.Iterate()}}
	for _, module := range Flags.KMods {
		path := filepath.Join("/sys/kernel/btf", module)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open %s: %v", path, err)
		}
		defer f.Close()

		modSpec, err := btf.LoadSplitSpecFromReader(f, Flags.BtfSpec)
		if err != nil {
			return fmt.Errorf("failed to load %s btf: %v", module, err)
		}
		iters = append(iters, iterator{module, modSpec.Iterate()})
	}

	for _, it := range iters {
		for it.iter.Next() {
			fn, ok := it.iter.Type.(*btf.Func)
			if !ok {
				continue
			}

			fnName := fn.Name

			if Flags.FilterFunc != "" && reg.FindString(fnName) != fnName {
				continue
			}

			if it.kmod != "" {
				fnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
			}
			if _, ok := availableFuncs[fnName]; !ok {
				continue
			}

			for i, p := range fn.Type.(*btf.FuncProto).Params {
				if i >= maxParamPos {
					break
				}
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" {
							name := fn.Name
							if Flags.UseKprobeMulti && it.kmod != "" {
								name = fmt.Sprintf("%s [%s]", name, it.kmod)
							}
							funcs[name] = i + 1
							break // it is assumed that there's only one sk_buff
						}
					}
				}
			}
		}
	}

	if len(funcs) == 0 {
		return fmt.Errorf("no matching kernel function found")
	}

	return nil
}

func GetFuncCount() int {
	return len(funcs)
}

func GetFuncsByPos() [][]string {
	ret := make([][]string, maxParamPos+1)
	for fn, pos := range funcs {
		ret[pos] = append(ret[pos], fn)
	}
	return ret
}

// Very hacky way to check whether multi-link kprobe is supported.
func HaveBPFLinkKprobeMulti() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_kpm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceKprobeMulti,
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	opts := link.KprobeMultiOptions{Symbols: []string{"vprintk"}}
	link, err := link.KretprobeMulti(prog, opts)
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}
