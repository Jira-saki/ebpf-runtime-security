// monitor.go
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
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
type ConnectEvent struct {
	Pid   uint32
	Daddr uint32
	Dport uint16
	Pad   uint16
	Comm  [16]byte
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

	// แปะ Hook เข้ากับ Tracepoint sys_enter_connect
	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		log.Fatalf("Attaching sys_enter_connect failed: %v", err)
	}
	defer tpConnect.Close()

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
for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// 1. ถ้าขนาดตรงกับ ConnectEvent (28 bytes) ให้แสดง Connect
		var connEvt ConnectEvent
		if len(record.RawSample) == binary.Size(connEvt) {
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &connEvt); err == nil {
				comm := strings.TrimRight(string(connEvt.Comm[:]), "\x00")
				ip := net.IPv4(byte(connEvt.Daddr), byte(connEvt.Daddr>>8), byte(connEvt.Daddr>>16), byte(connEvt.Daddr>>24))

				fmt.Printf("[CONNECT] PID: %-6d | Comm: %-12s -> %s:%d\n", connEvt.Pid, comm, ip, connEvt.Dport)
			}
			continue
		}

		// 2. ถ้าขนาดตรงกับ Event ของ openat ให้ข้ามไปก่อน (หรือไม่ต้องแสดง)
		// continue
	}
}