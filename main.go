// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/cilium/pwru/internal/pwru"
)

func main() {
	if err := pwru.InitConfig(); err != nil {
		log.Fatalf("Failed to initilize configuration: %s", err)
	}

	if pwru.Config.ShowVersion {
		fmt.Printf("pwru %s\n", pwru.Version)
		os.Exit(0)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 4096,
		Max: 4096,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	if err := pwru.InitUtils(); err != nil {
		log.Fatalf("Failed to initilize utilities: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = pwru.Config.BtfSpec

	var objs pwru.KProbeObjects
	var err error
	switch {
	case pwru.Config.OutputSkb && pwru.Config.UseKprobeMulti:
		objs = &KProbeMultiPWRUObjects{}
		err = LoadKProbeMultiPWRUObjects(objs, &opts)
	case pwru.Config.OutputSkb:
		objs = &KProbePWRUObjects{}
		err = LoadKProbePWRUObjects(objs, &opts)
	case pwru.Config.UseKprobeMulti:
		objs = &KProbeMultiPWRUWithoutOutputSKBObjects{}
		err = LoadKProbeMultiPWRUWithoutOutputSKBObjects(objs, &opts)
	default:
		objs = &KProbePWRUWithoutOutputSKBObjects{}
		err = LoadKProbePWRUWithoutOutputSKBObjects(objs, &opts)
	}

	if err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	kprobe1 := objs.GetKprobeSkb1()
	kprobe2 := objs.GetKprobeSkb2()
	kprobe3 := objs.GetKprobeSkb3()
	kprobe4 := objs.GetKprobeSkb4()
	kprobe5 := objs.GetKprobeSkb5()

	cfgMap := objs.GetCfgMap()
	events := objs.GetEvents()
	printStackMap := objs.GetPrintStackMap()
	var printSkbMap *ebpf.Map
	if pwru.Config.OutputSkb {
		printSkbMap = objs.(pwru.KProbeMapsWithOutputSKB).GetPrintSkbMap()
	}

	log.Printf("Per cpu buffer size: %d bytes\n", pwru.Config.PerCPUBuffer)
	pwru.ConfigBPFMap(cfgMap)

	var kprobes []link.Link
	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Detaching kprobes...")
			bar := pb.StartNew(len(kprobes))
			for _, kp := range kprobes {
				_ = kp.Close()
				bar.Increment()
			}
			bar.Finish()

		default:
			for _, kp := range kprobes {
				_ = kp.Close()
			}
		}
	}()

	msg := "kprobe"
	if pwru.Config.UseKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching kprobes (via %s)...\n", msg)
	ignored := 0
	bar := pb.StartNew(pwru.GetFuncCount())
	funcsByPos := pwru.GetClassifiedFuncs()
	for pos, fns := range funcsByPos {
		var fn *ebpf.Program
		switch pos {
		case 0:
			continue
		case 1:
			fn = kprobe1
		case 2:
			fn = kprobe2
		case 3:
			fn = kprobe3
		case 4:
			fn = kprobe4
		case 5:
			fn = kprobe5
		default:
			ignored += 1
			continue
		}

		if !pwru.Config.UseKprobeMulti {
			for _, name := range fns {
				select {
				case <-ctx.Done():
					bar.Finish()
					return
				default:
				}

				kp, err := link.Kprobe(name, fn, nil)
				bar.Increment()
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						log.Fatalf("Opening kprobe %s: %s\n", name, err)
					} else {
						ignored += 1
					}
				} else {
					kprobes = append(kprobes, kp)
				}
			}
		} else {
			select {
			case <-ctx.Done():
				bar.Finish()
				return
			default:
			}

			opts := link.KprobeMultiOptions{Symbols: funcsByPos[pos]}
			kp, err := link.KprobeMulti(fn, opts)
			bar.Add(len(fns))
			if err != nil {
				log.Fatalf("Opening kprobe-multi for pos %d: %s\n", pos, err)
			}
			kprobes = append(kprobes, kp)
		}
	}
	bar.Finish()
	log.Printf("Attached (ignored %d)\n", ignored)

	rd, err := perf.NewReader(events, pwru.Config.PerCPUBuffer)
	if err != nil {
		log.Fatalf("Creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()

		if err := rd.Close(); err != nil {
			log.Fatalf("Closing perf event reader: %s", err)
		}
	}()

	log.Println("Listening for events..")

	if pwru.Config.ReadyFile != "" {
		file, err := os.Create(pwru.Config.ReadyFile)
		if err != nil {
			log.Fatalf("Failed to create ready file: %s", err)
		}
		file.Close()
	}

	if err := pwru.InitOutput(printSkbMap, printStackMap); err != nil {
		log.Fatalf("Failed to initilize output writer: %s", err)
	}
	pwru.PrintHeader()

	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Received signal, exiting program..")
		default:
			log.Printf("Printed %d events, exiting program..\n", pwru.Config.OutputLimitLines)
		}
	}()

	var event pwru.Event
	runForever := pwru.Config.OutputLimitLines == 0
	for i := pwru.Config.OutputLimitLines; i > 0 || runForever; i-- {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %s", err)
		}

		if record.LostSamples != 0 {
			log.Printf("Perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Parsing perf event: %s", err)
			continue
		}

		pwru.Print(&event)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
