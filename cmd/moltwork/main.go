package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"time"

	"moltwork/internal/api"
	"moltwork/internal/config"
	"moltwork/internal/connector"
	"moltwork/internal/crypto"
	"moltwork/internal/health"
	"moltwork/internal/identity"
	"moltwork/internal/logging"
	"moltwork/internal/store"
)

//go:embed all:frontend
var frontendFiles embed.FS

//go:embed all:skill
var skillFiles embed.FS

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
		f := parseFlags(os.Args[2:])
		if len(f.rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: moltwork bootstrap <platform> <bot-token>")
			fmt.Fprintln(os.Stderr, "  e.g.: moltwork bootstrap slack xoxb-your-slack-bot-token")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "The workspace domain is auto-detected from the token via auth.test.")
			os.Exit(1)
		}
		runBootstrap(f.rest[0], f.rest[1], f)

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
	fmt.Println("  bootstrap <platform> <token>  Bootstrap a new workspace (domain auto-detected)")
	fmt.Println("  key export                   Export agent keys (encrypted backup)")
	fmt.Println("  key import                   Import agent keys from backup")
	fmt.Println("  version                      Print version")
	fmt.Println()
	fmt.Println("Flags (for run and bootstrap):")
	fmt.Println("  --data-dir <path>            Data directory (default: ~/.moltwork)")
	fmt.Println("  --port <number>              API server port (default: 9700)")
	fmt.Println("  --gossip-port <number>       Fixed gossip port (default: random)")
	fmt.Println("  --bootstrap-peers <addrs>    Comma-separated multiaddrs for peer discovery")
	fmt.Println("  --public-port <number>       Public port for sync endpoints on 0.0.0.0 (default: disabled)")
	fmt.Println("  --sync-url <url>             HTTP sync URL to advertise (default: auto-detect)")
	fmt.Println("  --sync-peers <urls>          Comma-separated HTTP URLs for chain sync")
	fmt.Println("  --serve-relay                Enable relay service for other agents")
	fmt.Println("  --advertise-addr <ip>        Public IP to advertise (for cloud VPS)")
}

// parsedFlags holds CLI flags parsed from args.
type parsedFlags struct {
	dataDir        string
	port           int
	gossipPort     int
	publicPort     int
	bootstrapPeers []string
	syncURL        string
	syncPeers      []string
	serveRelay    bool   // enable relay service for other agents
	advertiseAddr string // public IP to advertise (for cloud VPS)
	rest           []string
}

// parseFlags extracts --data-dir, --port, and --bootstrap-peers from args.
func parseFlags(args []string) parsedFlags {
	var f parsedFlags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--data-dir":
			if i+1 < len(args) {
				f.dataDir = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &f.port)
				i++
			}
		case "--bootstrap-peers":
			if i+1 < len(args) {
				// Comma-separated list of multiaddrs.
				for _, p := range strings.Split(args[i+1], ",") {
					if p = strings.TrimSpace(p); p != "" {
						f.bootstrapPeers = append(f.bootstrapPeers, p)
					}
				}
				i++
			}
		case "--gossip-port":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &f.gossipPort)
				i++
			}
		case "--public-port":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &f.publicPort)
				i++
			}
		case "--sync-url":
			if i+1 < len(args) {
				f.syncURL = args[i+1]
				i++
			}
		case "--sync-peers":
			if i+1 < len(args) {
				for _, p := range strings.Split(args[i+1], ",") {
					if p = strings.TrimSpace(p); p != "" {
						f.syncPeers = append(f.syncPeers, p)
					}
				}
				i++
			}
		case "--serve-relay":
			f.serveRelay = true
		case "--advertise-addr":
			if i+1 < len(args) {
				f.advertiseAddr = args[i+1]
				i++
			}
		default:
			f.rest = append(f.rest, args[i])
		}
	}
	return f
}

func applyFlags(cfg *config.Config, f parsedFlags) {
	if f.dataDir != "" {
		cfg.DataDir = f.dataDir
	}
	if f.port != 0 {
		cfg.WebUIPort = f.port
	}
	if f.gossipPort != 0 {
		cfg.ListenPort = f.gossipPort
	}
	if len(f.bootstrapPeers) > 0 {
		cfg.BootstrapPeers = append(cfg.BootstrapPeers, f.bootstrapPeers...)
	}
	if f.publicPort != 0 {
		cfg.PublicPort = f.publicPort
	}
	if f.syncURL != "" {
		cfg.SyncURL = f.syncURL
	}
	if len(f.syncPeers) > 0 {
		cfg.SyncPeers = append(cfg.SyncPeers, f.syncPeers...)
	}
	if f.serveRelay {
		cfg.ServeRelay = true
	}
	if f.advertiseAddr != "" {
		cfg.AdvertiseAddr = f.advertiseAddr
	}
}

func runServer() {
	// Catch panics and log them before exiting (bug 11 — silent crashes)
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "PANIC: %v\n", r)
			os.Stderr.Sync()
			os.Exit(1)
		}
	}()

	log := logging.New("main")
	cfg := config.Default()
	f := parseFlags(os.Args[2:])
	applyFlags(&cfg, f)

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
	// Embed skill files (agent documentation served without auth)
	skillFS, err := fs.Sub(skillFiles, "skill")
	if err != nil {
		log.Warn("skill files not available", map[string]any{"error": err.Error()})
	} else {
		srv.SetSkillFiles(skillFS)
	}
	// Embed the frontend (built from web/ into cmd/moltwork/frontend/)
	frontendFS, err := fs.Sub(frontendFiles, "frontend")
	if err != nil {
		log.Warn("frontend not available", map[string]any{"error": err.Error()})
	} else {
		srv.SetFrontend(frontendFS)
	}

	srv.Start()
	defer srv.Close()

	// Start public sync server if configured
	if cfg.PublicPort > 0 {
		if err := srv.StartPublicSync(cfg.PublicPort); err != nil {
			log.Fatal("start public sync server", map[string]any{"error": err.Error()})
		}
		fmt.Printf("Public sync server on 0.0.0.0:%d\n", cfg.PublicPort)
	}

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

func runBootstrap(platform, botToken string, f parsedFlags) {
	log := logging.New("bootstrap")
	cfg := config.Default()
	applyFlags(&cfg, f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Step 1: Verify the token and auto-detect workspace domain
	fmt.Printf("Verifying %s token...\n", platform)
	var domain string
	switch platform {
	case "slack":
		verifier := identity.NewSlackVerifier()
		pid, err := verifier.Verify(ctx, botToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Token verification failed: %v\n", err)
			os.Exit(1)
		}
		domain = pid.WorkspaceDomain
		fmt.Printf("Workspace: %s (user: %s)\n", domain, pid.DisplayName)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported platform: %s\n", platform)
		os.Exit(1)
	}

	// Step 2: Start connector and bootstrap
	conn := connector.New(cfg)
	if err := conn.Start(ctx); err != nil {
		log.Fatal("start connector", map[string]any{"error": err.Error()})
	}
	defer conn.Close()

	if err := conn.Bootstrap(platform, domain); err != nil {
		log.Fatal("bootstrap", map[string]any{"error": err.Error()})
	}

	// Step 3: Store the platform token (so /api/join and the watcher can use it)
	if err := conn.KeyDB().SetPlatformToken([]byte(botToken), platform, domain); err != nil {
		log.Fatal("store platform token", map[string]any{"error": err.Error()})
	}

	// Step 4: Create #moltwork-agents in Slack and post the first announcement
	conn.AnnounceOwnJoinToSlack("Bootstrap Agent", "", "")

	// NOTE: We do NOT post the gossip address here. The bootstrap starts a
	// temporary gossip node that exits when this command finishes. The real
	// gossip address is only stable after `moltwork run` starts — the join
	// request watcher in connector.go handles posting it automatically.

	fmt.Printf("Workspace bootstrapped for %s (%s)\n", domain, platform)
	fmt.Printf("Agent key: %x\n", conn.KeyPair().Public[:8])
	fmt.Println("Run 'moltwork run' to start the server, then call /api/join to register.")
}

func runKeyExport() {
	log := logging.New("key-export")
	cfg := config.Default()
	f := parseFlags(os.Args[3:])
	applyFlags(&cfg, f)

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
	if len(f.rest) > 0 {
		outputPath = f.rest[0]
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
	f := parseFlags(os.Args[3:])
	applyFlags(&cfg, f)

	inputPath := "moltwork-key-backup.bin"
	if len(f.rest) > 0 {
		inputPath = f.rest[0]
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

