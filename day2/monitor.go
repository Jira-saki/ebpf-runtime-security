// monitor.go
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Event struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	// ปลดล็อกขีดจำกัดหน่วยความจำ memlock สำหรับ eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock failed: %v", err)
	}

	// โหลดโปรแกรม BPF เข้า Kernel
	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("Loading BPF objects failed: %v", err)
	}
	defer objs.Close()

	// แปะ Hook เข้ากับ Tracepoint sys_enter_openat
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("Attaching tracepoint failed: %v", err)
	}
	defer tp.Close()

	// เปิดอ่านข้อมูลจาก Ring Buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader failed: %v", err)
	}
	defer rd.Close()

	fmt.Println("[*] eBPF Probe loaded! Monitoring sys_enter_openat in real-time...")

	// ดักรอสัญญาณปิดโปรแกรม (Ctrl+C)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		_ = rd.Close()
	}()

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("\n[*] Stopping eBPF monitor...")
				return
			}
			continue
		}

		// แปลง binary data กลับมาเป็นโครงสร้าง Struct
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		comm := strings.TrimRight(string(event.Comm[:]), "\x00")
		filename := strings.TrimRight(string(event.Filename[:]), "\x00")

		// กรองเฉพาะพฤติกรรมที่แตะโฟลเดอร์ uploads หรือไฟล์ .php
		if strings.Contains(filename, "uploads") || strings.HasSuffix(filename, ".php") {
			fmt.Printf("\033[1;31m[!] [KERNEL TRACE] PID: %d (%s) opened file: %s\033[0m\n", event.Pid, comm, filename)
		}
	}
}
