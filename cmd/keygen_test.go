package cmd

import (
	"os"
	"testing"

	"github.com/urfave/cli/v3"
)

// newKeygenTestApp creates a minimal CLI app wrapping keygenAction for testing.
func newKeygenTestApp() *cli.App {
	app := cli.NewApp()
	app.Name = "test"
	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "signer"},
		&cli.StringFlag{Name: "tlsHost"},
	}
	app.Action = keygenAction
	return app
}

func TestKeygenAction_TLSHostWithoutTrustProxy(t *testing.T) {
	// This test verifies that --tlsHost generates TLS certificates
	// without requiring --trustProxy (the bug was that trustProxy gated TLS generation)

	tempDir, err := os.MkdirTemp("", "keygen_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origDir)

	app := newKeygenTestApp()
	err = app.Run([]string{"test", "--tlsHost=test.example.com"})
	if err != nil {
		t.Fatalf("keygenAction with --tlsHost failed: %v", err)
	}

	// Verify TLS certificate and key files were created
	certFile := "test.example.com.crt"
	keyFile := "test.example.com.pem"

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("TLS certificate file %s was not created", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Errorf("TLS private key file %s was not created", keyFile)
	}
}

func TestKeygenAction_RequiresSignerOrTLSHost(t *testing.T) {
	app := newKeygenTestApp()

	// Should fail when neither --signer nor --tlsHost provided
	err := app.Run([]string{"test"})
	if err == nil {
		t.Error("keygenAction should return error when neither --signer nor --tlsHost is provided")
	}
}

func TestKeygenAction_SignerOnly(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keygen_signer_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origDir)

	app := newKeygenTestApp()
	err = app.Run([]string{"test", "--signer=test@mail.i2p"})
	if err != nil {
		t.Fatalf("keygenAction with --signer failed: %v", err)
	}

	// Verify signing certificate was created
	certFile := "test_at_mail.i2p.crt"
	keyFile := "test_at_mail.i2p.pem"

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("signing certificate file %s was not created", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Errorf("signing key file %s was not created", keyFile)
	}
}

func TestKeygenAction_BothSignerAndTLSHost(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keygen_both_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origDir)

	app := newKeygenTestApp()
	err = app.Run([]string{"test", "--signer=test@mail.i2p", "--tlsHost=test.example.com"})
	if err != nil {
		t.Fatalf("keygenAction with both flags failed: %v", err)
	}

	// Verify both signing and TLS files were created
	expectedFiles := []string{
		"test_at_mail.i2p.crt",
		"test_at_mail.i2p.pem",
		"test.example.com.crt",
		"test.example.com.pem",
	}

	for _, f := range expectedFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("expected file %s was not created", f)
		}
	}
}

func TestNewKeygenCommand_NoTrustProxyFlag(t *testing.T) {
	cmd := NewKeygenCommand()
	if cmd == nil {
		t.Fatal("NewKeygenCommand() returned nil")
	}

	// Verify the command does NOT have a trustProxy flag
	// (it was previously reading an undefined flag, causing the bug)
	for _, flag := range cmd.Flags {
		names := flag.Names()
		for _, name := range names {
			if name == "trustProxy" {
				t.Error("keygen command should not have a trustProxy flag — TLS generation should not be gated behind it")
			}
		}
	}

	// Verify the command HAS the expected flags
	hasFlags := map[string]bool{"signer": false, "tlsHost": false}
	for _, flag := range cmd.Flags {
		for _, name := range flag.Names() {
			if _, ok := hasFlags[name]; ok {
				hasFlags[name] = true
			}
		}
	}
	for name, found := range hasFlags {
		if !found {
			t.Errorf("keygen command is missing expected flag --%s", name)
		}
	}
}
