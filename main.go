package main

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func main() {
	// 1. Syscall: openat
	fd, err := unix.Openat(unix.AT_FDCWD, "/etc/hostname", unix.O_RDONLY, 0)
	if err != nil {
		fmt.Printf("Error openat: %v\n", err)
		return
	}
	defer unix.Close(fd) // 4. Syscall: close

	// 2. จอง Buffer
	buf := make([]byte, 64)

	// 3. Syscall: read
	n, err := unix.Read(fd, buf)
	if err != nil {
		fmt.Printf("Error read: %v\n", err)
		return
	}

	// 4. Syscall: write ลง fd 1 (Stdout)
	_, err = unix.Write(1, buf[:n])
	if err != nil {
		fmt.Printf("Error write: %v\n", err)
		return
	}
}
