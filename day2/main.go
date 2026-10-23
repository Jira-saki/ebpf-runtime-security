package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const uploadDir = "/tmp/uploads"

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read Body Error", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	filename := fmt.Sprintf("payload_%d.php", time.Now().Unix())
	targetPath := filepath.Join(uploadDir, filename)

	// จุดนี้จะ trigger system call: openat() และ write()
	err = os.WriteFile(targetPath, data, 0644)
	if err != nil {
		http.Error(w, "Write File Error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] [ALERT] New file dropped: %s (%d bytes) from %s\n", targetPath, len(data), r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Uploaded to %s\n", targetPath)))
}

func main() {
	_ = os.MkdirAll(uploadDir, 0755)
	http.HandleFunc("/upload", uploadHandler)

	fmt.Println("[*] Blue Team Target Server listening on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
