package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestMonitor(role string) *Monitor {
	cfg := &Config{Vantage: "astral-id", Role: role, IntervalSec: 60, FailThreshold: 3, RecoverThreshold: 2,
		CertWarnDays: 14, RemindHours: 6, HeartbeatHourMSK: 9, PeerStaleCycles: 5,
		SilenceFile: filepath.Join(os.TempDir(), "astral-monitor-test-nosilence")}
	cfg.Peer.Name = "frankfurt"
	return &Monitor{cfg: cfg, local: map[string]*Result{}, eng: &Engine{Alerts: map[string]*AlertState{}, Started: time.Now().Add(-time.Hour)}}
}

// A DOWN decided while the secondary was not the sender must be announced
// when it takes over (the failover gap).
func TestSecondaryTakeoverReannouncesDown(t *testing.T) {
	m := newTestMonitor("secondary")
	m.local["id"] = &Result{Label: "astral ID", Target: "https://id.astralnet.io/readyz", Detail: "timeout", FailStreak: 9}
	m.eng.Alerts["id"] = &AlertState{Down: true, SentDown: true, Since: time.Now().Add(-20 * time.Minute)}
	m.eng.Alerts["ok"] = &AlertState{}
	m.eng.PeerStale = 0 // primary alive: not the sender
	m.deliver(nil, nil)
	if m.eng.WasSender {
		t.Fatal("secondary must not be sender while primary is fresh")
	}
	m.eng.PeerStale = 5 // primary silent: takeover
	cycle := []string{"[astral monitor] DOWN · other (x)\nnew"}
	re := m.takeover(cycle)
	if len(re) != 1 || !strings.Contains(re[0], "DOWN · astral ID (id)") || !strings.Contains(re[0], "re-announced") {
		t.Fatalf("unexpected takeover messages: %q", re)
	}
	if hubSeverity(strings.SplitN(re[0], "\n", 2)[0]) != "critical" {
		t.Fatal("re-announced DOWN must be critical")
	}
	// A DOWN decided in the same cycle is not duplicated.
	cycle = []string{"[astral monitor] DOWN · astral ID (id)\nhttps://…"}
	if re := m.takeover(cycle); len(re) != 0 {
		t.Fatalf("duplicate DOWN: %q", re)
	}
}

func TestFileAge(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "b-1.dump")
	os.WriteFile(old, []byte("x"), 0o600)
	past := time.Now().Add(-30 * time.Hour)
	os.Chtimes(old, past, past)
	c := Check{Type: "file-age", Glob: filepath.Join(dir, "b-*"), MaxAgeHours: 26}
	if ok, d := checkFileAge(c); ok {
		t.Fatalf("30h old file passed: %s", d)
	}
	os.WriteFile(filepath.Join(dir, "b-2.dump"), []byte("x"), 0o600)
	if ok, d := checkFileAge(c); !ok {
		t.Fatalf("fresh file failed: %s", d)
	}
	if ok, _ := checkFileAge(Check{Glob: filepath.Join(dir, "none-*")}); ok {
		t.Fatal("missing files passed")
	}
}
