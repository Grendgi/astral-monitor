// astral-monitor: external probes for the astral infrastructure.
//
// One small static binary per vantage point (Frankfurt, astral-id host). Every
// interval it runs the checks from config.json, writes its results to
// status.json, pulls the peer vantage's status.json over a forced-command SSH
// key, and decides alerts from both views:
//
//   - DOWN      when every vantage that runs the check has failed it
//     failThreshold times in a row (a stale/unreachable peer drops
//     out, so one vantage decides alone);
//   - RECOVERED when every such vantage has passed recoverThreshold times in a row;
//   - reminder  every remindHours while still down;
//   - flapping  4 transitions within an hour mute that check for an hour;
//   - cert      certificate under certWarnDays — once a day per check;
//   - heartbeat daily at heartbeatHourMSK with an "all green" (or not) summary;
//   - probe silent: the peer's status is stale for peerStaleCycles cycles.
//
// Both vantages run the same decision engine; only the sender delivers to
// Telegram: the primary always, the secondary only while the primary's status
// is stale. Telegram credentials come from the environment (EnvironmentFile,
// root-only 600): TG_BOT_TOKEN, TG_CHAT_ID. No third-party dependencies.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var msk = time.FixedZone("MSK", 3*3600)

// ---------------------------------------------------------------- config

type Check struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Type     string `json:"type"` // https | smtp | dns | tcp
	Disabled bool   `json:"disabled,omitempty"`
	Test     bool   `json:"test,omitempty"` // messages prefixed "[test]"

	// https
	URL          string `json:"url,omitempty"`
	Expect       []int  `json:"expect,omitempty"`
	JSONReady    bool   `json:"jsonReady,omitempty"`    // body JSON must have ready:true
	BodyContains string `json:"bodyContains,omitempty"` // substring required in body
	Insecure     bool   `json:"insecure,omitempty"`     // skip TLS verification (and cert days)

	// smtp / tcp
	Addr       string `json:"addr,omitempty"`
	StartTLS   bool   `json:"starttls,omitempty"`
	ServerName string `json:"serverName,omitempty"`

	// dns
	Server  string     `json:"server,omitempty"` // 1.1.1.1:53
	Lookups []DNSQuery `json:"lookups,omitempty"`

	TimeoutSec int `json:"timeoutSec,omitempty"`
}

type DNSQuery struct {
	Type   string `json:"type"` // A | MX
	Name   string `json:"name"`
	Expect string `json:"expect"` // IP for A, host for MX
}

type Config struct {
	Vantage          string  `json:"vantage"`
	Role             string  `json:"role"` // primary | secondary
	IntervalSec      int     `json:"intervalSec"`
	FailThreshold    int     `json:"failThreshold"`
	RecoverThreshold int     `json:"recoverThreshold"`
	CertWarnDays     int     `json:"certWarnDays"`
	RemindHours      float64 `json:"remindHours"`
	HeartbeatHourMSK int     `json:"heartbeatHourMSK"`
	PeerStaleCycles  int     `json:"peerStaleCycles"`
	Peer             struct {
		Name    string `json:"name"`
		SSH     string `json:"ssh"` // root@host
		KeyFile string `json:"keyFile"`
	} `json:"peer"`
	StateDir    string  `json:"stateDir"`
	SilenceFile string  `json:"silenceFile"`
	Checks      []Check `json:"checks"`
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&c.IntervalSec, 60)
	def(&c.FailThreshold, 3)
	def(&c.RecoverThreshold, 2)
	def(&c.CertWarnDays, 14)
	def(&c.PeerStaleCycles, 5)
	if c.HeartbeatHourMSK <= 0 || c.HeartbeatHourMSK > 23 {
		c.HeartbeatHourMSK = 9
	}
	if c.RemindHours <= 0 {
		c.RemindHours = 6
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/astral-monitor"
	}
	if c.SilenceFile == "" {
		c.SilenceFile = filepath.Join(filepath.Dir(path), "silence")
	}
	if c.Vantage == "" {
		return nil, errors.New("vantage is required")
	}
	seen := map[string]bool{}
	for _, ch := range c.Checks {
		if ch.Name == "" || seen[ch.Name] {
			return nil, fmt.Errorf("check name empty or duplicate: %q", ch.Name)
		}
		seen[ch.Name] = true
	}
	return c, nil
}

// ---------------------------------------------------------------- results

type Result struct {
	Label      string    `json:"label,omitempty"`
	Target     string    `json:"target,omitempty"`
	Test       bool      `json:"test,omitempty"`
	OK         bool      `json:"ok"`
	Detail     string    `json:"detail"`
	CertDays   *int      `json:"certDays,omitempty"`
	CertHost   string    `json:"certHost,omitempty"`
	FailStreak int       `json:"failStreak"`
	OKStreak   int       `json:"okStreak"`
	FirstFail  time.Time `json:"firstFail,omitempty"`
	At         time.Time `json:"at"`
	DurationMs int64     `json:"durationMs"`
}

type Status struct {
	Vantage       string             `json:"vantage"`
	Role          string             `json:"role"`
	TS            time.Time          `json:"ts"`
	IntervalSec   int                `json:"intervalSec"`
	SilencedUntil *time.Time         `json:"silencedUntil,omitempty"`
	Checks        map[string]*Result `json:"checks"`
}

func target(c Check) string {
	switch c.Type {
	case "https":
		return c.URL
	case "dns":
		return "@" + c.Server
	default:
		return c.Addr
	}
}

func runCheck(c Check) (ok bool, detail string, certDays *int, certHost string) {
	timeout := time.Duration(c.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	switch c.Type {
	case "https":
		return checkHTTPS(c, timeout)
	case "smtp":
		return checkSMTP(c, timeout)
	case "dns":
		ok, detail := checkDNS(c, timeout)
		return ok, detail, nil, ""
	case "tcp":
		conn, err := net.DialTimeout("tcp", c.Addr, timeout)
		if err != nil {
			return false, shortErr(err), nil, ""
		}
		conn.Close()
		return true, "connected", nil, ""
	}
	return false, "unknown check type " + c.Type, nil, ""
}

func daysLeft(state *tls.ConnectionState) *int {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	d := int(time.Until(state.PeerCertificates[0].NotAfter).Hours() / 24)
	return &d
}

func checkHTTPS(c Check, timeout time.Duration) (bool, string, *int, string) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return false, "bad url", nil, ""
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: c.Insecure},
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest("GET", c.URL, nil)
	req.Header.Set("User-Agent", "astral-monitor/1")
	resp, err := client.Do(req)
	if err != nil {
		return false, shortErr(err), nil, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	var cert *int
	if !c.Insecure {
		cert = daysLeft(resp.TLS)
	}
	expect := c.Expect
	if len(expect) == 0 {
		expect = []int{200}
	}
	codeOK := false
	for _, e := range expect {
		if resp.StatusCode == e {
			codeOK = true
		}
	}
	if !codeOK {
		return false, fmt.Sprintf("HTTP %d (want %v)", resp.StatusCode, expect), cert, u.Hostname()
	}
	if c.JSONReady {
		var v struct {
			Ready *bool `json:"ready"`
		}
		if json.Unmarshal(body, &v) != nil || v.Ready == nil || !*v.Ready {
			return false, fmt.Sprintf("HTTP %d but ready!=true: %s", resp.StatusCode, clip(string(body), 120)), cert, u.Hostname()
		}
	}
	if c.BodyContains != "" && !strings.Contains(string(body), c.BodyContains) {
		return false, fmt.Sprintf("HTTP %d but body lacks %q", resp.StatusCode, c.BodyContains), cert, u.Hostname()
	}
	return true, fmt.Sprintf("HTTP %d", resp.StatusCode), cert, u.Hostname()
}

func checkSMTP(c Check, timeout time.Duration) (bool, string, *int, string) {
	host, _, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return false, "bad addr", nil, ""
	}
	sn := c.ServerName
	if sn == "" {
		sn = host
	}
	conn, err := net.DialTimeout("tcp", c.Addr, timeout)
	if err != nil {
		return false, shortErr(err), nil, sn
	}
	conn.SetDeadline(time.Now().Add(timeout + 10*time.Second))
	defer conn.Close()
	cl, err := smtp.NewClient(conn, sn) // reads the 220 banner
	if err != nil {
		return false, "banner: " + shortErr(err), nil, sn
	}
	defer cl.Close()
	if err := cl.Hello("monitor.astralnet.io"); err != nil {
		return false, "EHLO: " + shortErr(err), nil, sn
	}
	if !c.StartTLS {
		cl.Quit()
		return true, "banner+EHLO ok", nil, sn
	}
	if ok, _ := cl.Extension("STARTTLS"); !ok {
		return false, "STARTTLS not offered", nil, sn
	}
	if err := cl.StartTLS(&tls.Config{ServerName: sn}); err != nil {
		return false, "STARTTLS: " + shortErr(err), nil, sn
	}
	state, _ := cl.TLSConnectionState()
	cl.Quit()
	return true, "banner+STARTTLS ok", daysLeft(&state), sn
}

func checkDNS(c Check, timeout time.Duration) (bool, string) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", c.Server)
		},
	}
	var bad []string
	for _, q := range c.Lookups {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		found := false
		var got []string
		var err error
		switch strings.ToUpper(q.Type) {
		case "MX":
			var mx []*net.MX
			mx, err = r.LookupMX(ctx, q.Name)
			for _, m := range mx {
				h := strings.TrimSuffix(m.Host, ".")
				got = append(got, h)
				if strings.EqualFold(h, q.Expect) {
					found = true
				}
			}
		default:
			var ips []string
			ips, err = r.LookupHost(ctx, q.Name)
			for _, ip := range ips {
				got = append(got, ip)
				if ip == q.Expect {
					found = true
				}
			}
		}
		cancel()
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s %s: %s", q.Type, q.Name, shortErr(err)))
		} else if !found {
			bad = append(bad, fmt.Sprintf("%s %s = %v (want %s)", q.Type, q.Name, got, q.Expect))
		}
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	return true, fmt.Sprintf("%d answers ok", len(c.Lookups))
}

func shortErr(err error) string {
	s := err.Error()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 100 {
		s = s[i+2:]
	}
	return clip(s, 140)
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------------------------------------------------------------- alert state

type AlertState struct {
	Down         bool        `json:"down"`
	Since        time.Time   `json:"since,omitempty"`
	LastNotify   time.Time   `json:"lastNotify,omitempty"`
	SentDown     bool        `json:"sentDown"` // what the channel was last told
	Transitions  []time.Time `json:"transitions,omitempty"`
	MutedUntil   time.Time   `json:"mutedUntil,omitempty"`
	Partial      bool        `json:"partial,omitempty"`
	CertWarnDay  string      `json:"certWarnDay,omitempty"`
	LastDetail   string      `json:"lastDetail,omitempty"`
	LastDowntime string      `json:"lastDowntime,omitempty"`
}

type Engine struct {
	Alerts        map[string]*AlertState `json:"alerts"`
	HeartbeatDay  string                 `json:"heartbeatDay"`
	Incidents     []time.Time            `json:"incidents,omitempty"`
	PeerStale     int                    `json:"peerStale"`
	PeerSilentHit bool                   `json:"peerSilentAlerted"`
	Pending       []string               `json:"pending,omitempty"`
	Started       time.Time              `json:"-"`
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------- telegram

// sendAlert delivers through the astral-notify hub when HUB_URL/HUB_TOKEN are
// set (astral-id vantage: http://127.0.0.1:9311), falling back to direct
// Telegram if the hub is down or refuses. Without HUB_URL it is sendTelegram.
func sendAlert(text string) error {
	hub, tok := os.Getenv("HUB_URL"), os.Getenv("HUB_TOKEN")
	if hub == "" || tok == "" {
		return sendTelegram(text)
	}
	err := sendHub(hub, tok, text)
	if err == nil {
		return nil
	}
	log.Printf("hub: %v — falling back to direct Telegram", err)
	return sendTelegram(text)
}

// hubSeverity maps the monitor's message kinds onto the hub's levels.
func hubSeverity(first string) string {
	switch {
	case strings.Contains(first, "] DOWN"), strings.Contains(first, "STILL DOWN"):
		return "critical"
	case strings.Contains(first, "WARN"), strings.Contains(first, "FLAPPING"), strings.Contains(first, "PARTIAL"), strings.Contains(first, "CERT"):
		return "warning"
	}
	return "info"
}

func sendHub(base, token, text string) error {
	parts := strings.SplitN(text, "\n", 2)
	title := strings.TrimSpace(strings.Replace(parts[0], "[astral monitor] ", "", 1))
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}
	payload, _ := json.Marshal(map[string]string{
		"source":   "monitor",
		"severity": hubSeverity(parts[0]),
		"title":    title,
		"text":     body,
		"code":     "astral-monitor",
	})
	req, err := http.NewRequest("POST", strings.TrimRight(base, "/")+"/v1/notify", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, clip(string(b), 200))
	}
	return nil
}

func sendTelegram(text string) error {
	token, chat := os.Getenv("TG_BOT_TOKEN"), os.Getenv("TG_CHAT_ID")
	if token == "" || chat == "" {
		return errors.New("TG_BOT_TOKEN/TG_CHAT_ID not set")
	}
	form := url.Values{"chat_id": {chat}, "text": {text}, "disable_web_page_preview": {"true"}}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm("https://api.telegram.org/bot"+token+"/sendMessage", form)
	if err != nil {
		// Never let the URL (with the token) reach the log.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("telegram: %v", ue.Err)
		}
		return errors.New("telegram: request failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode != 200 {
		return fmt.Errorf("telegram: HTTP %d %s", resp.StatusCode, clip(string(body), 200))
	}
	return nil
}

// ---------------------------------------------------------------- silence

// The silence file holds an RFC3339 time ("until") or "forever"; absent = not silenced.
func silencedUntil(path string) *time.Time {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "forever" {
		t := time.Now().Add(100 * 365 * 24 * time.Hour)
		return &t
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || time.Now().After(t) {
		return nil
	}
	return &t
}

// ---------------------------------------------------------------- monitor

type Monitor struct {
	cfgPath string
	cfg     *Config
	local   map[string]*Result
	eng     *Engine
}

func (m *Monitor) statePath(name string) string { return filepath.Join(m.cfg.StateDir, name) }

func (m *Monitor) runChecks() {
	now := time.Now()
	next := map[string]*Result{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, c := range m.cfg.Checks {
		if c.Disabled {
			continue
		}
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			ok, detail, cert, certHost := runCheck(c)
			if !ok { // one quick retry against blips
				time.Sleep(2 * time.Second)
				ok, detail, cert, certHost = runCheck(c)
			}
			r := &Result{Label: c.Label, Target: target(c), Test: c.Test, OK: ok, Detail: detail, CertDays: cert, CertHost: certHost, At: now, DurationMs: time.Since(start).Milliseconds()}
			mu.Lock()
			prev := m.local[c.Name]
			if prev != nil {
				r.FailStreak, r.OKStreak, r.FirstFail = prev.FailStreak, prev.OKStreak, prev.FirstFail
				// Keep the last known cert days when this run could not see the cert.
				if r.CertDays == nil && !ok {
					r.CertDays, r.CertHost = prev.CertDays, prev.CertHost
				}
			}
			if ok {
				r.OKStreak++
				r.FailStreak = 0
				r.FirstFail = time.Time{}
			} else {
				if r.FailStreak == 0 {
					r.FirstFail = now
				}
				r.FailStreak++
				r.OKStreak = 0
			}
			next[c.Name] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	m.local = next
}

func (m *Monitor) fetchPeer() *Status {
	if m.cfg.Peer.SSH == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + filepath.Join(filepath.Dir(m.cfgPath), "known_hosts"),
		"-i", m.cfg.Peer.KeyFile, m.cfg.Peer.SSH, "status"}
	out, err := exec.CommandContext(ctx, "ssh", args...).Output()
	if err != nil {
		log.Printf("peer %s: fetch failed: %v", m.cfg.Peer.Name, err)
		return nil
	}
	st := &Status{}
	if err := json.Unmarshal(out, st); err != nil {
		log.Printf("peer %s: bad status: %v", m.cfg.Peer.Name, err)
		return nil
	}
	return st
}

func peerFresh(st *Status, interval int) bool {
	if st == nil {
		return false
	}
	iv := st.IntervalSec
	if iv <= 0 {
		iv = interval
	}
	return time.Since(st.TS) < time.Duration(3*iv+30)*time.Second
}

type view struct {
	vantage string
	r       *Result
}

func fmtMSK(t time.Time) string { return t.In(msk).Format("02.01 15:04 MSK") }

func fmtDur(d time.Duration) string {
	m := int(d.Minutes() + 0.5)
	if m < 60 {
		return fmt.Sprintf("%d min", m)
	}
	if m < 48*60 {
		return fmt.Sprintf("%dh %02dm", m/60, m%60)
	}
	return fmt.Sprintf("%dd %dh", m/1440, (m%1440)/60)
}

func checkTitle(name string, r *Result) string {
	t := name
	if r != nil && r.Label != "" {
		t = r.Label + " (" + name + ")"
	}
	if r != nil && r.Test {
		t = "[test] " + t
	}
	return t
}

// cycle runs the decision engine and returns the messages to deliver.
func (m *Monitor) decide(peer *Status) []string {
	cfg, e, now := m.cfg, m.eng, time.Now()
	fresh := peerFresh(peer, cfg.IntervalSec)
	var msgs []string

	// Peer silence (monitor-of-monitor), local only.
	if fresh {
		if e.PeerSilentHit {
			msgs = append(msgs, fmt.Sprintf("[astral monitor] RECOVERED · probe %s is reporting again", cfg.Peer.Name))
		}
		e.PeerStale, e.PeerSilentHit = 0, false
	} else if cfg.Peer.SSH != "" {
		e.PeerStale++
		if e.PeerStale >= cfg.PeerStaleCycles && !e.PeerSilentHit && time.Since(e.Started) > 10*time.Minute {
			e.PeerSilentHit = true
			msgs = append(msgs, fmt.Sprintf("[astral monitor] WARN · probe %s is silent for %d cycles (status unreachable or stale); checks now decided by %s alone",
				cfg.Peer.Name, e.PeerStale, cfg.Vantage))
		}
	}

	names := map[string]bool{}
	for n := range m.local {
		names[n] = true
	}
	if fresh {
		for n := range peer.Checks {
			names[n] = true
		}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	today := now.In(msk).Format("2006-01-02")
	var certLines []string
	for _, name := range sorted {
		var views []view
		if r := m.local[name]; r != nil {
			views = append(views, view{cfg.Vantage, r})
		}
		if fresh {
			if r := peer.Checks[name]; r != nil {
				views = append(views, view{peer.Vantage, r})
			}
		}
		if len(views) == 0 {
			continue
		}
		a := e.Alerts[name]
		if a == nil {
			a = &AlertState{}
			e.Alerts[name] = a
		}
		allFail, allOK := true, true
		var first time.Time
		for _, v := range views {
			if v.r.FailStreak < cfg.FailThreshold {
				allFail = false
			}
			if v.r.OKStreak < cfg.RecoverThreshold {
				allOK = false
			}
			if !v.r.FirstFail.IsZero() && (first.IsZero() || v.r.FirstFail.Before(first)) {
				first = v.r.FirstFail
			}
		}
		ref := views[0].r
		title := checkTitle(name, ref)
		detailLines := func() string {
			var b strings.Builder
			for _, v := range views {
				state := "ok"
				if !v.r.OK {
					state = fmt.Sprintf("FAIL x%d", v.r.FailStreak)
				}
				fmt.Fprintf(&b, "\n%s: %s — %s", v.vantage, state, v.r.Detail)
			}
			return b.String()
		}

		var msg string
		switch {
		case !a.Down && allFail:
			a.Down, a.Since = true, first
			if a.Since.IsZero() {
				a.Since = now
			}
			a.LastDetail = ref.Detail
			e.Incidents = append(e.Incidents, now)
			msg = fmt.Sprintf("[astral monitor] DOWN · %s\n%s%s\nsince %s", title, ref.Target, detailLines(), fmtMSK(a.Since))
		case a.Down && allOK:
			a.Down = false
			a.LastDowntime = fmtDur(now.Sub(a.Since))
			msg = fmt.Sprintf("[astral monitor] RECOVERED · %s\n%s%s\ndown for %s", title, ref.Target, detailLines(), a.LastDowntime)
		case a.Down && a.SentDown && now.Sub(a.LastNotify) > time.Duration(cfg.RemindHours*float64(time.Hour)) && now.After(a.MutedUntil):
			a.LastNotify = now
			msgs = append(msgs, fmt.Sprintf("[astral monitor] STILL DOWN · %s for %s%s", title, fmtDur(now.Sub(a.Since)), detailLines()))
		}
		if msg != "" {
			// Flap damping: the 4th transition within an hour mutes the check for an hour.
			var recent []time.Time
			for _, t := range a.Transitions {
				if now.Sub(t) < time.Hour {
					recent = append(recent, t)
				}
			}
			recent = append(recent, now)
			a.Transitions = recent
			switch {
			case now.Before(a.MutedUntil):
				log.Printf("muted (flapping): %s", strings.SplitN(msg, "\n", 2)[0])
			case len(recent) >= 4:
				a.MutedUntil = now.Add(time.Hour)
				msgs = append(msgs, fmt.Sprintf("[astral monitor] FLAPPING · %s changed state %d times in the last hour; muted until %s (current: %s)",
					title, len(recent), fmtMSK(a.MutedUntil), map[bool]string{true: "DOWN", false: "up"}[a.Down]))
				a.SentDown, a.LastNotify = a.Down, now
			default:
				msgs = append(msgs, msg)
				a.SentDown, a.LastNotify = a.Down, now
			}
		} else if !now.Before(a.MutedUntil) && !a.MutedUntil.IsZero() {
			// Mute over: tell the channel if the state differs from what it last heard.
			a.MutedUntil = time.Time{}
			if a.SentDown != a.Down {
				msgs = append(msgs, fmt.Sprintf("[astral monitor] %s · %s (after flapping mute)%s", map[bool]string{true: "DOWN", false: "RECOVERED"}[a.Down], title, detailLines()))
				a.SentDown, a.LastNotify = a.Down, now
			}
		}

		// Partial: one vantage failing for 15+ cycles while the other passes.
		if len(views) == 2 && !a.Down {
			oneBad := (views[0].r.FailStreak >= 15 && views[1].r.OK) || (views[1].r.FailStreak >= 15 && views[0].r.OK)
			if oneBad && !a.Partial {
				a.Partial = true
				msgs = append(msgs, fmt.Sprintf("[astral monitor] PARTIAL · %s fails from one vantage only (route/vantage problem?)%s", title, detailLines()))
			} else if views[0].r.OK && views[1].r.OK {
				a.Partial = false
			}
		}

		// Certificates.
		minDays, host := 1<<30, ""
		for _, v := range views {
			if v.r.CertDays != nil && *v.r.CertDays < minDays {
				minDays, host = *v.r.CertDays, v.r.CertHost
			}
		}
		if host != "" && minDays < cfg.CertWarnDays && a.CertWarnDay != today {
			a.CertWarnDay = today
			certLines = append(certLines, fmt.Sprintf("%s (%s): %d days left", host, name, minDays))
		}
	}
	if len(certLines) > 0 {
		msgs = append(msgs, fmt.Sprintf("[astral monitor] CERT · expiring in under %d days:\n%s", cfg.CertWarnDays, strings.Join(certLines, "\n")))
	}

	// Daily heartbeat.
	nowMSK := now.In(msk)
	if nowMSK.Hour() >= cfg.HeartbeatHourMSK && e.HeartbeatDay != today {
		e.HeartbeatDay = today
		msgs = append(msgs, m.summary(peer, fresh))
	}

	// Forget incidents older than a day.
	var inc []time.Time
	for _, t := range e.Incidents {
		if now.Sub(t) < 24*time.Hour {
			inc = append(inc, t)
		}
	}
	e.Incidents = inc
	return msgs
}

func (m *Monitor) summary(peer *Status, fresh bool) string {
	var down []string
	vantages := []string{m.cfg.Vantage}
	if fresh {
		vantages = append(vantages, peer.Vantage)
	}
	names := make([]string, 0, len(m.eng.Alerts))
	for n := range m.eng.Alerts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if m.eng.Alerts[n].Down {
			down = append(down, n)
		}
	}
	minDays, minHost := 1<<30, ""
	count := 0
	for _, src := range []map[string]*Result{m.local, func() map[string]*Result {
		if fresh {
			return peer.Checks
		}
		return nil
	}()} {
		for _, r := range src {
			count++
			if r.CertDays != nil && *r.CertDays < minDays {
				minDays, minHost = *r.CertDays, r.CertHost
			}
		}
	}
	head := "all green"
	if len(down) > 0 {
		head = "DOWN: " + strings.Join(down, ", ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[astral monitor] daily · %s\n%d check results from %s", head, count, strings.Join(vantages, " + "))
	if !fresh && m.cfg.Peer.Name != "" {
		fmt.Fprintf(&b, " (probe %s not reporting)", m.cfg.Peer.Name)
	}
	if minHost != "" {
		fmt.Fprintf(&b, "\nnearest cert expiry: %s in %d days", minHost, minDays)
	}
	fmt.Fprintf(&b, "\nincidents in the last 24h: %d", len(m.eng.Incidents))
	return b.String()
}

func (m *Monitor) isSender(peer *Status) bool {
	if m.cfg.Role != "secondary" {
		return true
	}
	// The secondary takes over only while the primary has been silent long enough.
	return m.eng.PeerStale >= m.cfg.PeerStaleCycles && time.Since(m.eng.Started) > 10*time.Minute
}

func (m *Monitor) deliver(msgs []string, peer *Status) {
	if !m.isSender(peer) {
		m.eng.Pending = nil
		for _, s := range msgs {
			log.Printf("not sender (primary active), skip: %s", strings.SplitN(s, "\n", 2)[0])
		}
		return
	}
	silence := silencedUntil(m.cfg.SilenceFile)
	if silence == nil && peerFresh(peer, m.cfg.IntervalSec) && peer.SilencedUntil != nil && time.Now().Before(*peer.SilencedUntil) {
		silence = peer.SilencedUntil
	}
	queue := append(m.eng.Pending, msgs...)
	m.eng.Pending = nil
	for _, s := range queue {
		if silence != nil {
			log.Printf("silenced until %s, drop: %s", silence.Format(time.RFC3339), strings.SplitN(s, "\n", 2)[0])
			continue
		}
		if err := sendAlert(s); err != nil {
			log.Printf("send failed (%v), will retry: %s", err, strings.SplitN(s, "\n", 2)[0])
			if len(m.eng.Pending) < 20 {
				m.eng.Pending = append(m.eng.Pending, s)
			}
			continue
		}
		log.Printf("sent: %s", strings.SplitN(s, "\n", 2)[0])
	}
}

func (m *Monitor) writeStatus() {
	st := Status{Vantage: m.cfg.Vantage, Role: m.cfg.Role, TS: time.Now(), IntervalSec: m.cfg.IntervalSec, SilencedUntil: silencedUntil(m.cfg.SilenceFile), Checks: m.local}
	if err := writeJSON(m.statePath("status.json"), st, 0o644); err != nil {
		log.Printf("write status: %v", err)
	}
	if err := writeJSON(m.statePath("engine.json"), m.eng, 0o600); err != nil {
		log.Printf("write engine: %v", err)
	}
}

func (m *Monitor) loop() {
	for {
		start := time.Now()
		if cfg, err := loadConfig(m.cfgPath); err != nil {
			log.Printf("config reload failed, keeping previous: %v", err)
		} else {
			m.cfg = cfg
		}
		m.runChecks()
		m.writeStatus()
		peer := m.fetchPeer()
		msgs := m.decide(peer)
		m.deliver(msgs, peer)
		m.writeStatus()
		var failing []string
		for n, r := range m.local {
			if !r.OK {
				failing = append(failing, fmt.Sprintf("%s(x%d: %s)", n, r.FailStreak, r.Detail))
			}
		}
		sort.Strings(failing)
		log.Printf("cycle: %d checks, %d failing %v, peer fresh=%v", len(m.local), len(failing), failing, peerFresh(peer, m.cfg.IntervalSec))
		if d := time.Duration(m.cfg.IntervalSec)*time.Second - time.Since(start); d > 0 {
			time.Sleep(d)
		}
	}
}

func newMonitor(cfgPath string) (*Monitor, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return nil, err
	}
	m := &Monitor{cfgPath: cfgPath, cfg: cfg, local: map[string]*Result{}, eng: &Engine{Alerts: map[string]*AlertState{}}}
	// Resume streaks and alert state across restarts.
	var st Status
	if readJSON(m.statePath("status.json"), &st) == nil && st.Checks != nil && time.Since(st.TS) < 10*time.Minute {
		m.local = st.Checks
	}
	if readJSON(m.statePath("engine.json"), m.eng) != nil || m.eng.Alerts == nil {
		m.eng = &Engine{Alerts: map[string]*AlertState{}}
		// First start: the first heartbeat is the next 09:00, not now.
		if time.Now().In(msk).Hour() >= cfg.HeartbeatHourMSK {
			m.eng.HeartbeatDay = time.Now().In(msk).Format("2006-01-02")
		}
	}
	m.eng.Started = time.Now()
	return m, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `astral-monitor [-c config.json] <command>
  run                 probe loop (systemd service)
  once                run the checks once and print results (no alerts)
  status              print the last status and alert state
  silence <dur|off>   mute Telegram (e.g. 2h, 30m, forever, off) — honoured by the peer too
  send-test <text>    send one Telegram message (prefix it with [test])`)
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	cfgPath := "/opt/astral-monitor/config.json"
	args := os.Args[1:]
	if len(args) >= 2 && args[0] == "-c" {
		cfgPath, args = args[1], args[2:]
	}
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "run":
		m, err := newMonitor(cfgPath)
		if err != nil {
			log.Fatalf("start: %v", err)
		}
		log.Printf("astral-monitor %s (%s), %d checks, every %ds, peer %s", m.cfg.Vantage, m.cfg.Role, len(m.cfg.Checks), m.cfg.IntervalSec, m.cfg.Peer.Name)
		m.loop()
	case "once":
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		m := &Monitor{cfgPath: cfgPath, cfg: cfg, local: map[string]*Result{}}
		m.runChecks()
		names := make([]string, 0, len(m.local))
		for n := range m.local {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			r := m.local[n]
			cert := ""
			if r.CertDays != nil {
				cert = fmt.Sprintf(" cert=%dd", *r.CertDays)
			}
			fmt.Printf("%-5v %-18s %-45s %s%s (%dms)\n", map[bool]string{true: "OK", false: "FAIL"}[r.OK], n, r.Target, r.Detail, cert, r.DurationMs)
		}
	case "status":
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range []string{"status.json", "engine.json"} {
			raw, err := os.ReadFile(filepath.Join(cfg.StateDir, f))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("== %s\n%s\n", f, raw)
		}
		if s := silencedUntil(cfg.SilenceFile); s != nil {
			fmt.Printf("silenced until %s\n", s.Format(time.RFC3339))
		}
	case "silence":
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		if len(args) < 2 {
			usage()
		}
		switch args[1] {
		case "off":
			os.Remove(cfg.SilenceFile)
			fmt.Println("silence off")
		case "forever":
			os.WriteFile(cfg.SilenceFile, []byte("forever\n"), 0o644)
			fmt.Println("silenced until further notice (astral-monitor silence off)")
		default:
			d, err := time.ParseDuration(args[1])
			if err != nil {
				log.Fatalf("bad duration: %v", err)
			}
			until := time.Now().Add(d).UTC().Format(time.RFC3339)
			os.WriteFile(cfg.SilenceFile, []byte(until+"\n"), 0o644)
			fmt.Println("silenced until", until)
		}
	case "send-test":
		if len(args) < 2 {
			usage()
		}
		if err := sendAlert(strings.Join(args[1:], " ")); err != nil {
			log.Fatal(err)
		}
		fmt.Println("sent")
	default:
		usage()
	}
}
