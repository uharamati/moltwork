package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"time"

	"moltwork/internal/api"
	"moltwork/internal/config"
	"moltwork/internal/connector"
	"moltwork/internal/crypto"
	"moltwork/internal/health"
	"moltwork/internal/logging"
	"moltwork/internal/store"
)

var version = "dev"
var commit = "unknown"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("moltwork %s (%s)\n", version, commit)

	case "run":
		runServer()

	case "bootstrap":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: moltwork bootstrap <platform> <workspace-domain>")
			fmt.Fprintln(os.Stderr, "  e.g.: moltwork bootstrap slack toriihq.slack.com")
			os.Exit(1)
		}
		runBootstrap(os.Args[2], os.Args[3])

	case "key":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: moltwork key <export|import>")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "export":
			runKeyExport()
		case "import":
			runKeyImport()
		default:
			fmt.Fprintf(os.Stderr, "unknown key command: %s\n", os.Args[2])
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("moltwork %s — distributed agent coordination workspace\n\n", version)
	fmt.Println("Commands:")
	fmt.Println("  run                          Start the connector and API server")
	fmt.Println("  bootstrap <platform> <domain> Bootstrap a new workspace")
	fmt.Println("  key export                   Export agent keys (encrypted backup)")
	fmt.Println("  key import                   Import agent keys from backup")
	fmt.Println("  version                      Print version")
}

func runServer() {
	log := logging.New("main")
	cfg := config.Default()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := connector.New(cfg)
	if err := conn.Start(ctx); err != nil {
		log.Fatal("start connector", map[string]any{"error": err.Error()})
	}
	defer conn.Close()

	// Open diagnostics database (expendable — don't fail startup if it breaks)
	diagDB, err := store.OpenDiagDB(cfg.DiagDBPath())
	if err != nil {
		log.Warn("diagnostics db unavailable, logs won't be queryable", map[string]any{"error": err.Error()})
	} else {
		conn.SetDiagDB(diagDB)
		defer diagDB.Close()
	}

	// Set up health checker
	hc := health.NewChecker(conn, version)
	hc.StartBackgroundRefresh(ctx, 5*time.Second)

	// Start API server
	srv, err := api.NewServer(conn, cfg.WebUIPort)
	if err != nil {
		log.Fatal("start API server", map[string]any{"error": err.Error()})
	}
	srv.SetVersion(version)
	srv.SetHealthChecker(hc)
	if diagDB != nil {
		srv.SetDiagDB(diagDB)
	}
	srv.Start()
	defer srv.Close()

	log.Info("moltwork running", map[string]any{
		"api":     srv.Addr(),
		"version": version,
	})

	fmt.Printf("Moltwork running at http://%s\n", srv.Addr())
	fmt.Printf("Bearer token written to: %s\n", conn.WebUITokenPath())

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
}

func runBootstrap(platform, domain string) {
	log := logging.New("bootstrap")
	cfg := config.Default()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := connector.New(cfg)
	if err := conn.Start(ctx); err != nil {
		log.Fatal("start connector", map[string]any{"error": err.Error()})
	}
	defer conn.Close()

	if err := conn.Bootstrap(platform, domain); err != nil {
		log.Fatal("bootstrap", map[string]any{"error": err.Error()})
	}

	fmt.Printf("Workspace bootstrapped for %s (%s)\n", domain, platform)
	fmt.Printf("Agent key: %x\n", conn.KeyPair().Public[:8])
}

func runKeyExport() {
	log := logging.New("key-export")
	cfg := config.Default()

	keyDB, err := store.OpenKeyDB(cfg.KeyDBPath())
	if err != nil {
		log.Fatal("open key db", map[string]any{"error": err.Error()})
	}
	defer keyDB.Close()

	pub, priv, err := keyDB.GetIdentity()
	if err != nil || pub == nil {
		fmt.Fprintln(os.Stderr, "No identity found. Run 'moltwork bootstrap' first.")
		os.Exit(1)
	}

	fmt.Print("Enter passphrase for key export: ")
	passphrase := make([]byte, 256)
	n, err := os.Stdin.Read(passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read passphrase")
		os.Exit(1)
	}
	// Trim newline
	for n > 0 && (passphrase[n-1] == '\n' || passphrase[n-1] == '\r') {
		n--
	}
	passphrase = passphrase[:n]
	if len(passphrase) == 0 {
		fmt.Fprintln(os.Stderr, "Passphrase cannot be empty")
		os.Exit(1)
	}
	defer crypto.Zero(passphrase)

	// Combine pub + priv for backup
	keyMaterial := append(pub, priv...)
	backup, err := crypto.BackupExport(keyMaterial, passphrase)
	if err != nil {
		log.Fatal("export", map[string]any{"error": err.Error()})
	}

	outputPath := "moltwork-key-backup.bin"
	if len(os.Args) > 3 {
		outputPath = os.Args[3]
	}

	if err := crypto.WriteKeyFile(outputPath, backup); err != nil {
		log.Fatal("write backup", map[string]any{"error": err.Error()})
	}

	fmt.Printf("Key exported to: %s\n", outputPath)
	fmt.Println("WARNING: This file + your passphrase = access to your agent's entire communication history.")
}

func runKeyImport() {
	log := logging.New("key-import")
	cfg := config.Default()

	inputPath := "moltwork-key-backup.bin"
	if len(os.Args) > 3 {
		inputPath = os.Args[3]
	}

	data, err := crypto.ReadKeyFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read backup file: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("Enter passphrase: ")
	passphrase := make([]byte, 256)
	n, err := os.Stdin.Read(passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read passphrase")
		os.Exit(1)
	}
	// Trim newline
	for n > 0 && (passphrase[n-1] == '\n' || passphrase[n-1] == '\r') {
		n--
	}
	passphrase = passphrase[:n]
	defer crypto.Zero(passphrase)

	keyMaterial, err := crypto.BackupImport(data, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to decrypt backup. Wrong passphrase?")
		os.Exit(1)
	}

	if len(keyMaterial) < 32+64 {
		fmt.Fprintln(os.Stderr, "Invalid key material")
		os.Exit(1)
	}

	pub := keyMaterial[:32]
	priv := keyMaterial[32:]

	keyDB, err := store.OpenKeyDB(cfg.KeyDBPath())
	if err != nil {
		log.Fatal("open key db", map[string]any{"error": err.Error()})
	}
	defer keyDB.Close()

	if err := keyDB.SetIdentity(pub, priv); err != nil {
		log.Fatal("store identity", map[string]any{"error": err.Error()})
	}

	fmt.Printf("Key imported successfully. Agent key: %x\n", pub[:8])
}
