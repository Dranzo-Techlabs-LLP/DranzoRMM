//go:build linux

package platform

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunAsUserLinux exercises the real run-as-user path (runuser, or direct
// credentials when runuser is missing). It needs root and an existing
// unprivileged account, so it is opt-in:
//
//	DRANZO_TEST_RUN_AS=<username> go test ./internal/platform/ -run RunAsUser
func TestRunAsUserLinux(t *testing.T) {
	name := os.Getenv("DRANZO_TEST_RUN_AS")
	if name == "" {
		t.Skip("set DRANZO_TEST_RUN_AS=<unprivileged user> (and run as root) to enable")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := lookupUser(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	p := New()

	// A script directory handed to the user: readable by them, not by others.
	dir, err := os.MkdirTemp("", "dranzo-job-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte("id -un; id -u; echo \"home=$HOME extra=$EXTRA\"; cat \"$0\" >/dev/null && echo readable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.GrantUser(script, u); err != nil {
		t.Fatal(err)
	}
	if err := p.GrantUser(dir, u); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code, err := p.Run(ctx, Command{
		Path: "/bin/sh", Args: []string{script}, Env: []string{"EXTRA=from-agent"},
		Stdout: &out, Stderr: &errOut, AsUser: u,
	})
	if err != nil || code != 0 {
		t.Fatalf("run as %s: code=%d err=%v stderr=%q", name, code, err, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || lines[0] != u.Name || lines[1] != u.UID || lines[3] != "readable" {
		t.Fatalf("unexpected output %q", out.String())
	}
	if !strings.Contains(lines[2], "extra=from-agent") || !strings.Contains(lines[2], "home="+u.Home) {
		t.Fatalf("environment not passed: %q", lines[2])
	}

	// The user cannot read the agent's root-only files.
	secret := filepath.Join(t.TempDir(), "device.key")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code, err = p.Run(ctx, Command{Path: "/bin/cat", Args: []string{secret}, Stdout: &out, Stderr: &errOut, AsUser: u})
	if err != nil {
		t.Fatal(err)
	}
	if code == 0 || out.Len() != 0 {
		t.Fatalf("user could read a root-only file (code %d)", code)
	}

	// Cancelling kills the user's process tree too.
	cctx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	defer stop()
	started := time.Now()
	_, err = p.Run(cctx, Command{Path: "/bin/sh", Args: []string{"-c", "sleep 60 & wait"}, AsUser: u})
	if err == nil || time.Since(started) > 10*time.Second {
		t.Fatalf("cancel did not stop the user process: err=%v after %v", err, time.Since(started))
	}
}

func TestMachineIDAndPendingRebootLinux(t *testing.T) {
	p := New()
	// Container images often ship an empty /etc/machine-id; only a populated one must be returned.
	if data, err := os.ReadFile("/etc/machine-id"); err == nil && ParseMachineID(string(data)) != "" {
		id, err := p.MachineID(context.Background())
		if err != nil || id != ParseMachineID(string(data)) {
			t.Fatalf("machine id: %q %v", id, err)
		}
	}
	if _, err := p.PendingReboot(context.Background()); err != nil {
		t.Logf("pending reboot check reported: %v", err)
	}
	if _, err := p.LoggedInUsers(context.Background()); err != nil {
		t.Fatalf("logged-in users: %v", err)
	}
}
