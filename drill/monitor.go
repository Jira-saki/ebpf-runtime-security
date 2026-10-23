package main

import (
	"bytes"
	"encoding/binary"
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

type bpfEvent struct {
	Pid       uint32
	Comm      [16]byte
	Filename  [256]byte
	EventType uint32
}

// ฟังก์ชันแปลง null-terminated C string เป็น Go string ที่สะอาด
func cleanCString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs tracerObjects
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed: %v", err)
	}
	defer objs.Close()

	// 1. แนบ Hook: sys_enter_openat
	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("Attaching openat failed: %v", err)
	}
	defer tpOpen.Close()

	// 2. แนบ Hook: sys_enter_execve
	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("Attaching execve failed: %v", err)
	}
	defer tpExec.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Creating ringbuf reader failed: %v", err)
	}
	defer rd.Close()

	fmt.Println("[*] eBPF Monitor ACTIVE: Watching both [openat] and [execve]...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[*] Exiting cleanly...")
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var event bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(event.Filename[:], "\x00"))

		// Event ประเภท 1: openat (เปิด/สร้างไฟล์)
		if event.EventType == 1 {
			if strings.Contains(filename, "uploads") || strings.HasSuffix(filename, ".php") {
				fmt.Printf("\033[31m[!] [FILE DROP] PID: %d (%s) opened: %s\033[0m\n", event.Pid, comm, filename)
			}
		}

		// Event ประเภท 2: execve (รันคำสั่ง)
		if event.EventType == 2 {
			if strings.Contains(filename, "whoami") || strings.Contains(filename, "sh") || strings.Contains(filename, "bash") {
				fmt.Printf("\033[33m[!] [CMD EXEC] PID: %d (%s) executed: %s\033[0m\n", event.Pid, comm, filename)
			}
		}
	}
}
