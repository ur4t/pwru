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
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// Currently libbpf only support getting first 5 params
const maxParamPos = 5

var utils struct {
	Funcs         map[string]int
	KsymAddr2Name map[uint64]string
	KsymsAddrs    []uint64
}

func findNearestSym(ip uint64) string {
	i := sort.Search(len(utils.KsymsAddrs), func(i int) bool {
		return utils.KsymsAddrs[i] > ip
	})
	if i == 0 {
		i += 1
	}
	return utils.KsymAddr2Name[utils.KsymsAddrs[i-1]]
}

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

func InitUtils() error {
	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	utils.Funcs = make(map[string]int)
	utils.KsymAddr2Name = make(map[uint64]string)

	reg, err := regexp.Compile(Config.FilterFunc)
	if err != nil {
		return fmt.Errorf("failed to compile regular expression %v", err)
	}

	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	iters := []iterator{{"", Config.BtfSpec.Iterate()}}
	for _, module := range Config.KMods {
		path := filepath.Join("/sys/kernel/btf", module)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open %s: %v", path, err)
		}
		defer f.Close()

		modSpec, err := btf.LoadSplitSpecFromReader(f, Config.BtfSpec)
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

			if Config.FilterFunc != "" && reg.FindString(fnName) != fnName {
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
							if Config.UseKprobeMulti && it.kmod != "" {
								name = fmt.Sprintf("%s [%s]", name, it.kmod)
							}
							utils.Funcs[name] = i + 1
							break // it is assumed that there's only one sk_buff
						}
					}
				}
			}
		}
	}

	if len(utils.Funcs) == 0 {
		return fmt.Errorf("no matching kernel function found")
	}

	outputStack := Config.OutputStack || len(Config.KMods) != 0

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name := line[2]
		if _, ok := utils.Funcs[name]; outputStack || ok {
			addr, err := strconv.ParseUint(line[0], 16, 64)
			if err != nil {
				return err
			}
			utils.KsymAddr2Name[addr] = name
			if outputStack {
				utils.KsymsAddrs = append(utils.KsymsAddrs, addr)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if outputStack {
		sort.Slice(utils.KsymsAddrs, func(i, j int) bool {
			return utils.KsymsAddrs[i] < utils.KsymsAddrs[j]
		})
	}

	return nil
}

func GetFuncCount() int {
	return len(utils.Funcs)
}

func GetClassifiedFuncs() [][]string {
	ret := make([][]string, maxParamPos+1)
	for fn, pos := range utils.Funcs {
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
