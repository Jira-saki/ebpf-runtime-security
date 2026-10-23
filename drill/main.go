package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	uploadDir := "/tmp/uploads"
	os.MkdirAll(uploadDir, 0755)

	filename := fmt.Sprintf("payload_%d.php", time.Now().Unix())
	filePath := filepath.Join(uploadDir, filename)

	err = os.WriteFile(filePath, body, 0644)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] [ALERT] New file dropped: %s (%d bytes) from %s\n", filePath, len(body), r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Uploaded to %s\n", filePath)))
}

func main() {
	http.HandleFunc("/upload", uploadHandler)
	fmt.Println("[*] Blue Team Target Server listening on :8080...")
	http.ListenAndServe(":8080", nil)
}
