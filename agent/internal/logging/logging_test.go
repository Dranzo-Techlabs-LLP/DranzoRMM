package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := NewWithWriter(&buf, slog.LevelDebug)
	const token = "dz_enroll_Abc123-_.xyz"
	const key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----"
	log.Info("enrolling with "+token,
		slog.String("token", token),
		slog.String("url", "https://host/enroll?t="+token),
		slog.Any("error", errors.New("server said: bad token "+token)),
		slog.String("body", "rm -rf / # secret script"),
		slog.String("pem", key),
		slog.String("password", "hunter2"),
		slog.String("harmless", "value"))
	out := buf.String()
	for _, secret := range []string{"Abc123", "MIGHAgEA", "rm -rf", "hunter2"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret %q leaked into the log: %s", secret, out)
		}
	}
	if !strings.Contains(out, `"harmless":"value"`) || !strings.Contains(out, Redacted) {
		t.Fatalf("unexpected log line: %s", out)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(out), &line); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
}

func TestForJobCarriesCorrelationIDs(t *testing.T) {
	var buf bytes.Buffer
	log := ForJob(NewWithWriter(&buf, slog.LevelInfo), "device-1", "job-1")
	log.Info("one")
	log.With(slog.String("k", "v")).Warn("two")
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var line map[string]any
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatal(err)
		}
		if line["device_id"] != "device-1" || line["job_run_id"] != "job-1" {
			t.Fatalf("correlation ids missing: %s", l)
		}
	}
}

func TestRotatingWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	w, err := NewRotatingWriter(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 59) + "\n") // 60 bytes: every second write rotates
	for i := 0; i < 10; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 { // agent.log, .1, .2
		t.Fatalf("expected 3 files, got %v", entries)
	}
	for _, e := range entries {
		fi, _ := e.Info()
		if fi.Size() > 100 {
			t.Fatalf("%s is %d bytes", e.Name(), fi.Size())
		}
		if os.PathSeparator == '/' && fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", e.Name(), fi.Mode().Perm())
		}
	}
}
