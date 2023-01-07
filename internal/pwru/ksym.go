package pwru

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
)

var ksymAddr2Name map[uint64]string = make(map[uint64]string)
var ksymsAddrs []uint64

func findNearestSym(ip uint64) string {
	i := sort.Search(len(ksymsAddrs), func(i int) bool {
		return ksymsAddrs[i] > ip
	})
	if i == 0 {
		i += 1
	}
	return ksymAddr2Name[ksymsAddrs[i-1]]
}

func InitKsyms(funcs Funcs, outputStack bool) error {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name := line[2]
		if outputStack || (funcs[name] > 0) {
			addr, err := strconv.ParseUint(line[0], 16, 64)
			if err != nil {
				return err
			}
			ksymAddr2Name[addr] = name
			if outputStack {
				ksymsAddrs = append(ksymsAddrs, addr)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if outputStack {
		sort.Slice(ksymsAddrs, func(i, j int) bool {
			return ksymsAddrs[i] < ksymsAddrs[j]
		})
	}

	return nil
}
