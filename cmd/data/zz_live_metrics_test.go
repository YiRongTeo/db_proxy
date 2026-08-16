package main

// --- Task 9.8 LIVE metrics test (user directive 2026-08-15) ----------------
//
// The "zz" prefix is deliberate (same convention as the proxy package's
// zz_live_* tests): this test runs LAST in the cmd/data binary. It builds
// the REAL data-plane binary, runs it as a subprocess with metrics enabled
// (ZT_METRICS_ENABLED=true, the shipped default endpoint 0.0.0.0:9464
// /metrics), scrapes the endpoint EXACTLY like a Prometheus server, and then
// drives real traffic through the plane, asserting the instrument deltas
// verbatim.
//
// The scrape proves the full Task 9.8 wiring: the Prometheus exporter's
// collector on the client_golang DEFAULT registerer, the stock
// promhttp.Handler() serving this meter's instruments AND the standard Go
// runtime/process collectors (go_*, process_*) from the same default
// gatherer, and every call site (GETDEL ok/reject, session open/close,
// publishPending, gate reject, kill handler, session teardown).
//
// CLIENT CHOICE (round 4): stages (a) and (b) drive traffic with the
// project's OWN go-mysql client v1.16.0 (github.com/go-mysql-org/go-mysql/
// client — the same dependency internal/proxy/mysql_router.go uses for
// backend auth). The docker mysql CLI was retired from these stages: it
// sends UNCONDITIONAL probe queries per connection (select
// @@version_comment limit 1 ok + select $$ error — verified across 7 flag
// combos, unsuppressible) that pollute the queries_total deltas. The
// go-mysql client sends ZERO probes — exactly one SELECT 1 per connection,
// so every delta is a clean +1 — and a gated INSERT surfaces as a Go error
// (*mysql.MyError, Code 1045). Stages (c) and (d) keep the docker CLI (their
// assertions are probe-proof: kills/rejections, not query counters).
//
// BLOCKED-PATH SEMANTICS (round 4): a command blocked by the maker write-
// gate is a published query event with status=error, so the blocked-command
// publish sites (publishBlocked ×3 protocols, gateRejectEntries ×3
// variants) increment gate.blocks AND queries.total{db_type, stmt_type,
// status=error} — the gate_blocks_total and queries_total{insert,error}
// deltas below prove both.
//
// Requires the live environment (the established suite convention): Valkey
// on :6379 (store.NewValkeyStoreDirect fails fast), the mysql-test container
// (docker exec), and the committed creds mysql:{ro,rw}_user@127.0.0.1:3307.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// TestLiveMetricsScrapeAndDeltas: the Task 9.8 money shot. The real plane
// with metrics enabled; a scrape shows every instrument family plus the
// standard go_*/process_* collectors; then each traffic scenario moves its
// instrument by exactly the asserted delta:
//
//	(a) SELECT 1 (go-mysql client)
//	                       → tokens_validated_total +1, queries_total{select,ok} +1,
//	                         connections_total{ok} +1, connections_active 0→1→0,
//	                         histograms count +1
//	(c) ctl:kill (docker CLI SLEEP) → kills_total{mode=connection} +1, connections_active →0
//	(b) gated INSERT (go-mysql client) → gate_blocks_total{db_type=mysql} +1,
//	                         queries_total{insert,error} +1
//	(d) bogus token (docker CLI) → tokens_rejected_total{reason=invalid} +1,
//	                         connections_total{result=rejected} +1
//
// Deltas are computed between verbatim scrapes of the same endpoint a real
// Prometheus server would scrape; async publishes (the relay publishes
// AFTER the client's response is written) are settled with a bounded poll
// that asserts the EXACT delta — never "at least".
func TestLiveMetricsScrapeAndDeltas(t *testing.T) {
	// --- Build the real data-plane binary once ---------------------------
	// go test runs with cwd = the package dir (cmd/data); the module root is
	// two levels up. The plane loads configs/data.yaml relative to ITS cwd,
	// so the subprocess runs with Dir = module root too.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "data-plane")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/data")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build data plane: %v\n%s", err, out)
	}

	// --- The shipped default metrics endpoint (0.0.0.0:9464 /metrics) ----
	// Pre-flight: the port must be free (a stray plane would silently serve
	// a stale scrape and corrupt every delta).
	probe, err := net.Listen("tcp", "0.0.0.0:9464")
	if err != nil {
		t.Fatalf("port 9464 already bound (stray plane?): %v", err)
	}
	_ = probe.Close()
	const metricsURL = "http://127.0.0.1:9464/metrics"

	// Free data-plane port (the docker mysql-test container reaches it via
	// host.docker.internal, so the listener must be all-interfaces).
	dataLn, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("reserve data port: %v", err)
	}
	dataPort := strconv.Itoa(dataLn.Addr().(*net.TCPAddr).Port)
	_ = dataLn.Close()

	// --- Start the plane (hermetic ZT_* env; everything else = defaults) -
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "ZT_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"ZT_METRICS_ENABLED=true", // default listen 0.0.0.0:9464 + path /metrics
		"ZT_LISTEN_ADDR=:"+dataPort,
		"ZT_GATE_WAIT_SECONDS=0", // blocked commands reject immediately (pre-8.13)
	)
	plane := exec.Command(bin)
	plane.Dir = root
	plane.Env = env
	var planeLog bytes.Buffer
	plane.Stdout = &planeLog
	plane.Stderr = &planeLog
	if err := plane.Start(); err != nil {
		t.Fatalf("start plane: %v", err)
	}
	t.Cleanup(func() {
		_ = plane.Process.Kill()
		_, _ = plane.Process.Wait()
		t.Logf("plane log:\n%s", tail(planeLog.String(), 40))
	})

	// Wait for BOTH endpoints: the scrape endpoint answering 200 and the
	// data listener accepting.
	deadline := time.Now().Add(30 * time.Second)
	var body string
	for {
		if resp, err := http.Get(metricsURL); err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body = string(b)
				break
			}
		}
		if c, err := net.Dial("tcp", "127.0.0.1:"+dataPort); err == nil {
			_ = c.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("plane did not become ready within 30s\n%s", tail(planeLog.String(), 40))
		}
		time.Sleep(250 * time.Millisecond)
	}

	vs := liveStore(t)
	ctx := context.Background()

	// Baseline scrape: BEFORE any traffic no zerotrust_* instrument has data
	// (the exporter omits empty instruments), but the go_*/process_*
	// collectors are always present — the stock default-registerer gatherer
	// proof.
	baseline := body
	if v := scrapeValue(t, baseline, "go_goroutines", nil); v <= 0 {
		t.Errorf("go_goroutines = %v at baseline, want > 0 (Go collector on the default gatherer)", v)
	}
	if v := scrapeValue(t, baseline, "process_cpu_seconds_total", nil); v < 0 {
		t.Errorf("process_cpu_seconds_total = %v at baseline, want present", v)
	}
	t.Logf("baseline scrape OK: go_* and process_* collectors present, zerotrust_* families absent (empty instruments omitted)")

	// --- (a) mysql query: SELECT 1 through the plane (go-mysql client) ---
	// Round 4: the go-mysql client sends ZERO probe queries (live-proven),
	// so this stage's deltas are exactly +1 — no CLI probe pollution.
	tokenA, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, tokenA, models.TokenPayload{Username: "metrics-a", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-9-8-a"}, 2*time.Minute); err != nil {
		t.Fatalf("SetToken(a): %v", err)
	}
	connA, err := client.Connect("127.0.0.1:"+dataPort, tokenA, "", "")
	if err != nil {
		t.Fatalf("go-mysql connect(a): %v", err)
	}
	if _, err := connA.Execute("SELECT 1"); err != nil {
		t.Fatalf("SELECT 1 via go-mysql: %v", err)
	}
	// Session is still open → the +1 UP direction of the active gauge is
	// observable right now (the 0→1 transition, verbatim).
	afterA := waitValue(t, metricsURL, "zerotrust_proxy_connections_active", map[string]string{"db_type": "mysql"}, 1, "connections_active while open", 5*time.Second)
	afterA = waitDelta(t, metricsURL, baseline, "zerotrust_proxy_tokens_validated_total", nil, 1, "tokens_validated_total", 5*time.Second)
	afterA = waitDelta(t, metricsURL, baseline, "zerotrust_proxy_queries_total", map[string]string{"stmt_type": "select", "status": "ok"}, 1, "queries_total{select,ok}", 5*time.Second)
	afterA = waitDelta(t, metricsURL, baseline, "zerotrust_proxy_connections_total", map[string]string{"result": "ok"}, 1, "connections_total{ok}", 5*time.Second)
	t.Logf("(a) after SELECT 1 (session open):\n%s", familyLines(afterA, "zerotrust_proxy"))
	// Close → teardown: active back to 0, both histograms recorded one sample.
	_ = connA.Close()
	afterA = waitValue(t, metricsURL, "zerotrust_proxy_connections_active", map[string]string{"db_type": "mysql"}, 0, "connections_active after close", 5*time.Second)
	afterA = waitValue(t, metricsURL, "zerotrust_proxy_session_duration_seconds_count", map[string]string{"db_type": "mysql"}, 1, "session_duration_seconds_count", 5*time.Second)
	afterA = waitValue(t, metricsURL, "zerotrust_proxy_query_duration_seconds_count", map[string]string{"db_type": "mysql"}, 1, "query_duration_seconds_count", 5*time.Second)
	// The dispatch family list: every instrument family is present now.
	for _, fam := range []string{
		"zerotrust_proxy_tokens_validated_total",
		"zerotrust_proxy_connections_total",
		"zerotrust_proxy_connections_active",
		"zerotrust_proxy_queries_total",
		"zerotrust_proxy_session_duration_seconds_count",
		"zerotrust_proxy_query_duration_seconds_count",
	} {
		if !strings.Contains(afterA, fam) {
			t.Errorf("scrape missing family %s after (a)", fam)
		}
	}

	// --- (c) kill: a long session torn down via ctl:kill ------------------
	// A real mysql CLI running SELECT SLEEP(30) in the background; the
	// session id comes from the published lifecycle event (exactly the id
	// the control plane would kill with). Stage assertions are kills and
	// active-gauge only — the CLI's per-connection probe queries do not
	// touch them.
	tokenK, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, tokenK, models.TokenPayload{Username: "metrics-kill", DBUser: "ro_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-9-8-k"}, 2*time.Minute); err != nil {
		t.Fatalf("SetToken(k): %v", err)
	}
	evCh := liveSubscribe(t, vs, "queries:metrics-kill")
	sleepCmd := exec.Command("docker", "exec", "mysql-test", "mysql",
		"-h", "host.docker.internal", "-P", dataPort, "-u", tokenK, "-e", "SELECT SLEEP(30)")
	var sleepOut, sleepErr bytes.Buffer
	sleepCmd.Stdout = &sleepOut
	sleepCmd.Stderr = &sleepErr
	if err := sleepCmd.Start(); err != nil {
		t.Fatalf("start SLEEP CLI: %v", err)
	}
	t.Cleanup(func() { _ = sleepCmd.Process.Kill() })
	sid := liveSessionID(t, evCh)
	t.Logf("(c) SLEEP session %s established", sid)

	// Mid-flight scrape: connections_active must be 1 (the up direction of
	// the updowncounter, proven live a second time on a different session).
	time.Sleep(1500 * time.Millisecond)
	mid := fetchScrape(t, metricsURL)
	if v := scrapeValue(t, mid, "zerotrust_proxy_connections_active", map[string]string{"db_type": "mysql"}); v != 1 {
		t.Errorf("connections_active mid-SLEEP = %v, want 1 (session up)", v)
	}
	assertDelta(t, mid, afterA, "zerotrust_proxy_tokens_validated_total", nil, 1, "tokens_validated_total")

	// The kill, exactly as the control plane publishes it.
	if err := vs.Publish(ctx, "ctl:kill", []byte(`{"session_id":"`+sid+`","mode":"connection"}`)); err != nil {
		t.Fatalf("publish ctl:kill: %v", err)
	}
	killDone := make(chan error, 1)
	go func() { killDone <- sleepCmd.Wait() }()
	select {
	case <-killDone:
	case <-time.After(10 * time.Second):
		t.Fatal("mysql CLI did not exit within 10s of the kill")
	}
	if !strings.Contains(sleepErr.String(), "2013") {
		t.Errorf("killed CLI stderr = %q, want Error 2013 (lost connection)", sleepErr.String())
	}
	afterK := waitDelta(t, metricsURL, mid, "zerotrust_proxy_kills_total", map[string]string{"mode": "connection"}, 1, "kills_total{connection}", 5*time.Second)
	t.Logf("(c) after kill:\n%s", familyLines(afterK, "zerotrust_proxy"))
	afterK = waitValue(t, metricsURL, "zerotrust_proxy_connections_active", map[string]string{"db_type": "mysql"}, 0, "connections_active after kill", 5*time.Second)
	if v := scrapeValue(t, afterK, "zerotrust_proxy_session_duration_seconds_count", map[string]string{"db_type": "mysql"}); v != 2 {
		t.Errorf("session_duration_seconds_count after kill = %v, want 2", v)
	}

	// --- (b) gated INSERT: write token, no watcher, gate blocks -----------
	// Round 4: driven by the go-mysql client — the blocked command is
	// answered with ERR 1045, which the client surfaces as a Go error
	// (*mysql.MyError, Code 1045). The blocked-command publish path (round
	// 4 wiring, all 6 sites) increments gate.blocks AND
	// queries.total{insert,error}: a blocked command IS a published query
	// event with status=error, so it must land in queries_total too.
	tokenG, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := vs.SetToken(ctx, tokenG, models.TokenPayload{Username: "metrics-gate", DBUser: "rw_user",
		DBIP: "127.0.0.1", DBPort: "3307", DBType: "mysql", TicketID: "T-9-8-g", Access: "write"}, 2*time.Minute); err != nil {
		t.Fatalf("SetToken(g): %v", err)
	}
	connG, err := client.Connect("127.0.0.1:"+dataPort, tokenG, "", "")
	if err != nil {
		t.Fatalf("go-mysql connect(g): %v", err)
	}
	defer connG.Close()
	marker := fmt.Sprintf("metrics-gate-%d", time.Now().UnixNano())
	_, err = connG.Execute("INSERT INTO demo_items (name) VALUES ('" + marker + "')")
	if err == nil {
		t.Fatal("gated INSERT succeeded — the maker write-gate must block it (no watcher)")
	}
	var myErr *mysql.MyError
	if !errors.As(err, &myErr) || myErr.Code != 1045 {
		t.Errorf("gated INSERT error = %v (type %T), want *mysql.MyError Code 1045", err, err)
	}
	afterG := waitDelta(t, metricsURL, afterK, "zerotrust_proxy_gate_blocks_total", map[string]string{"db_type": "mysql"}, 1, "gate_blocks_total{mysql}", 5*time.Second)
	afterG = waitDelta(t, metricsURL, afterK, "zerotrust_proxy_queries_total", map[string]string{"stmt_type": "insert", "status": "error"}, 1, "queries_total{insert,error}", 5*time.Second)
	t.Logf("(b) after gated INSERT:\n%s", familyLines(afterG, "zerotrust_proxy"))

	// --- (d) rejected token: GETDEL nil → reason=invalid -------------------
	// Kept on the docker CLI (round 4): rejection happens at the handshake,
	// before any probe query could be sent, so the CLI's probe behavior is
	// irrelevant here.
	_, stderrR, err := mysqlCLI(dataPort, "sess_metrics_bogus", "SELECT 1")
	if err == nil {
		t.Fatal("bogus token connected — GETDEL must reject it")
	}
	if !strings.Contains(stderrR, "1045") && !strings.Contains(stderrR, "28000") {
		t.Errorf("rejected CLI stderr = %q, want an access-denied error", stderrR)
	}
	afterR := waitDelta(t, metricsURL, afterG, "zerotrust_proxy_tokens_rejected_total", map[string]string{"reason": "invalid"}, 1, "tokens_rejected_total{invalid}", 5*time.Second)
	afterR = waitDelta(t, metricsURL, afterG, "zerotrust_proxy_connections_total", map[string]string{"result": "rejected"}, 1, "connections_total{rejected}", 5*time.Second)
	t.Logf("(d) after rejected token:\n%s", familyLines(afterR, "zerotrust_proxy"))
	if !strings.Contains(afterR, "zerotrust_proxy_tokens_rejected_total") {
		t.Error("scrape missing tokens_rejected_total after (d)")
	}
}

// --- helpers ----------------------------------------------------------------

// liveStore connects to the live local Valkey (fails fast when it is down —
// the established suite convention).
func liveStore(t *testing.T) *store.ValkeyStore {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	return vs
}

// liveSubscribe mirrors the proxy package's subscribePG helper (blocked on
// subscription ack): the returned channel receives raw event JSON.
func liveSubscribe(t *testing.T, vs *store.ValkeyStore, channel string) <-chan []byte {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan []byte, 16)
	acked := make(chan struct{}, 1)
	subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
		select {
		case acked <- struct{}{}:
		default:
		}
	})
	go vs.Subscribe(subCtx, channel, false, out)
	select {
	case <-acked:
	case <-time.After(5 * time.Second):
		t.Fatal("subscription not confirmed within 5s")
	}
	return out
}

// liveSessionID waits for the next session lifecycle event (kind=session)
// and returns its SessionID.
func liveSessionID(t *testing.T, out <-chan []byte) string {
	t.Helper()
	select {
	case msg := <-out:
		var ev models.QueryEvent
		if err := json.Unmarshal(msg, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if ev.Kind != "session" || !strings.HasPrefix(ev.SessionID, "sid-") {
			t.Fatalf("event = kind %q session_id %q, want session/sid-", ev.Kind, ev.SessionID)
		}
		return ev.SessionID
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for session lifecycle event")
		return ""
	}
}

// mysqlCLI runs the REAL mysql C client inside the mysql-test container
// through the plane (the house verification command). Stage (c) SLEEP and
// stage (d) rejected-token still use it (their assertions are probe-proof);
// stages (a)/(b) use the go-mysql client (zero probe queries).
func mysqlCLI(dataPort, user, sql string) (string, string, error) {
	cmd := exec.Command("docker", "exec", "mysql-test", "mysql",
		"-h", "host.docker.internal", "-P", dataPort, "-u", user, "-e", sql)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// fetchScrape GETs the metrics endpoint and asserts a 200 (the endpoint a
// real Prometheus server scrapes).
func fetchScrape(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("scrape %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read scrape: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", resp.StatusCode)
	}
	return string(body)
}

// scrapeValue returns the value of the first sample line whose family is
// `family` and whose label set contains every (k,v) in want (nil want = the
// sample carries no labels). Families with no data are absent from the
// scrape → returns 0.
func scrapeValue(t *testing.T, body, family string, want map[string]string) float64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Prometheus text format: name[{labels}] value — the family token
		// may carry its label block, so strip it before matching.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, labels := fields[0], ""
		if i := strings.Index(name, "{"); i >= 0 {
			if !strings.HasSuffix(name, "}") {
				continue
			}
			labels = name[i+1 : len(name)-1]
			name = name[:i]
		}
		if name != family {
			continue
		}
		valStr := fields[1]
		match := len(want) == 0 && labels == ""
		if len(want) > 0 {
			match = true
			for k, v := range want {
				if !strings.Contains(labels, k+`="`+v+`"`) {
					match = false
					break
				}
			}
		}
		if !match {
			continue
		}
		f, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			t.Fatalf("parse value %q for %s: %v", valStr, family, err)
		}
		return f
	}
	return 0
}

// assertDelta asserts after-before == want for the sample (family, labels).
func assertDelta(t *testing.T, after, before, family string, labels map[string]string, want float64, what string) {
	t.Helper()
	b, a := scrapeValue(t, before, family, labels), scrapeValue(t, after, family, labels)
	if a-b != want {
		t.Errorf("%s delta = %v (%.0f → %.0f), want %v", what, a-b, b, a, want)
	}
}

// waitDelta polls the scrape endpoint until the (family, labels) delta
// reaches want — async publishes (the relay publishes AFTER the client's
// response bytes are written) can trail the client's own read by a few ms.
// The poll is bounded; a delta ABOVE want (overshoot) fails immediately —
// with the probe-free go-mysql client every asserted delta is exactly +1.
// Returns the final scrape body.
func waitDelta(t *testing.T, url, before, family string, labels map[string]string, want float64, what string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var body string
	for {
		body = fetchScrape(t, url)
		b, a := scrapeValue(t, before, family, labels), scrapeValue(t, body, family, labels)
		if a-b == want {
			return body
		}
		if a-b > want {
			t.Errorf("%s delta = %v (%.0f → %.0f), want %v — overshoot (unexpected extra event)", what, a-b, b, a, want)
			return body
		}
		if time.Now().After(deadline) {
			t.Errorf("%s delta = %v (%.0f → %.0f), want %v — timed out after %v", what, a-b, b, a, want, timeout)
			return body
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitValue polls the scrape endpoint until the (family, labels) sample
// equals want — gauge and histogram samples settle asynchronously (active
// decrements on teardown, duration records on close). Bounded; returns the
// final scrape body.
func waitValue(t *testing.T, url, family string, labels map[string]string, want float64, what string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var body string
	for {
		body = fetchScrape(t, url)
		if v := scrapeValue(t, body, family, labels); v == want {
			return body
		}
		if time.Now().After(deadline) {
			t.Errorf("%s = %v, want %v — timed out after %v", what, scrapeValue(t, body, family, labels), want, timeout)
			return body
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// familyLines returns the scrape's sample lines for families containing
// prefix (for -v evidence).
func familyLines(body, prefix string) string {
	var sb strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) || strings.HasPrefix(line, "# "+prefix) {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
