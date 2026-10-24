package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type harness struct {
	t   *testing.T
	dir string
	ctx context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return &harness{t: t, dir: t.TempDir(), ctx: context.Background()}
}

func (h *harness) p(name string) string { return filepath.Join(h.dir, name) }

// run executes the CLI and returns exit code, stdout and stderr.
func (h *harness) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(h.ctx, args, &out, &errb)
	return code, out.String(), errb.String()
}

func (h *harness) ok(args ...string) string {
	h.t.Helper()
	code, out, errs := h.run(args...)
	if code != ExitOK {
		h.t.Fatalf("attestlog %v: exit %d\nstdout:\n%s\nstderr:\n%s", args, code, out, errs)
	}
	return out
}

func (h *harness) fails(want int, args ...string) string {
	h.t.Helper()
	code, out, errs := h.run(args...)
	if code != want {
		h.t.Fatalf("attestlog %v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", args, code, want, out, errs)
	}
	return out + errs
}

func (h *harness) write(name, content string) string {
	h.t.Helper()
	if err := os.WriteFile(h.p(name), []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return h.p(name)
}

const testPolicy = `{
  "version": 1,
  "allowedBuilderIds": ["https://ci.example.test/release@*"],
  "allowedSourceRepos": ["git+https://git.example.test/acme/app"],
  "allowedSourceRefs": ["refs/tags/v1"],
  "requireSourceDigest": true,
  "requireTransparencyLog": true
}`

// startServe runs "log serve" until the test ends and returns its URL.
func (h *harness) startServe(dataDir string) string {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrFile := h.p(filepath.Base(dataDir) + ".addr")
	done := make(chan int, 1)
	var errb bytes.Buffer
	go func() {
		done <- Run(ctx, []string{"log", "serve", "--data", dataDir, "--key", h.p("log.key"),
			"--addr", "127.0.0.1:0", "--addr-file", addrFile, "--log-level", "error"}, &bytes.Buffer{}, &errb)
	}()
	h.t.Cleanup(func() {
		cancel()
		select {
		case code := <-done:
			if code != ExitOK {
				h.t.Errorf("serve exited %d: %s", code, errb.String())
			}
		case <-time.After(10 * time.Second):
			h.t.Error("serve did not shut down")
		}
	})
	for range 200 {
		if data, err := os.ReadFile(addrFile); err == nil && len(data) > 0 {
			return "http://" + strings.TrimSpace(string(data))
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("server did not start")
	return ""
}

func TestEndToEndCLI(t *testing.T) {
	h := newHarness(t)
	art := h.write("app.bin", "release bytes")
	pol := h.write("policy.json", testPolicy)

	out := h.ok("keygen", "--alg", "ed25519", "--out", h.p("signer"))
	if !strings.Contains(out, "generated ed25519 key") {
		t.Fatal(out)
	}
	h.ok("keygen", "--alg", "ecdsa-p256", "--out", h.p("second"))
	h.fails(ExitFailed, "keygen", "--out", h.p("signer")) // refuses to clobber
	h.ok("keygen", "--out", h.p("signer"), "--force")
	h.ok("log", "keygen", "--origin", "log.example.test", "--out", h.p("log"))

	h.ok("attest", "--artifact", art, "--key", h.p("signer.key"), "--key", h.p("second.key"),
		"--builder-id", "https://ci.example.test/release@v3",
		"--source-repo", "git+https://git.example.test/acme/app", "--source-ref", "refs/tags/v1",
		"--source-digest", "gitCommit:"+strings.Repeat("a", 40), "--param", "os=linux",
		"--invocation-id", "42", "--started-on", "2026-01-01T00:00:00Z", "--finished-on", "2026-01-01T00:05:00Z")
	envPath := art + ".intoto.json"

	out = h.ok("inspect", "--attestation", envPath)
	if !strings.Contains(out, "https://slsa.dev/provenance/v1") || !strings.Contains(out, "signatures:  2") {
		t.Fatalf("inspect: %s", out)
	}

	url := h.startServe(h.p("data"))
	h.ok("log", "submit", "--server", url, "--log-key", h.p("log.vkey"), "--attestation", envPath,
		"--pubkey", h.p("signer.pub"), "--pubkey", h.p("second.pub"), "--out", h.p("app.bundle.json"))
	out = h.ok("log", "submit", "--server", url, "--log-key", h.p("log.vkey"), "--attestation", envPath,
		"--pubkey", h.p("signer.pub"), "--pubkey", h.p("second.pub"), "--out", h.p("again.bundle.json"))
	if !strings.Contains(out, "already logged") {
		t.Fatalf("duplicate submit: %s", out)
	}

	out = h.ok("verify", "--artifact", art, "--bundle", h.p("app.bundle.json"), "--pubkey", h.p("signer.pub"),
		"--policy", pol, "--log-key", h.p("log.vkey"))
	if !strings.Contains(out, "verification PASSED") || strings.Contains(out, "FAIL") {
		t.Fatalf("verify: %s", out)
	}
	out = h.ok("verify", "--artifact", art, "--bundle", h.p("app.bundle.json"), "--pubkey", h.p("signer.pub"),
		"--policy", pol, "--log-key", h.p("log.vkey"), "--json")
	if !strings.Contains(out, `"passed": true`) {
		t.Fatalf("verify --json: %s", out)
	}
	out = h.ok("inspect", "--bundle", h.p("app.bundle.json"))
	if !strings.Contains(out, "log receipt: index 0") {
		t.Fatalf("inspect bundle: %s", out)
	}

	// Policy requires the log, so a bare envelope fails.
	out = h.fails(ExitFailed, "verify", "--artifact", art, "--attestation", envPath, "--pubkey", h.p("signer.pub"), "--policy", pol)
	if !strings.Contains(out, "[FAIL] transparency-log") {
		t.Fatalf("missing log: %s", out)
	}
	tampered := h.write("tampered.bin", "release bytes!")
	out = h.fails(ExitFailed, "verify", "--artifact", tampered, "--bundle", h.p("app.bundle.json"),
		"--pubkey", h.p("signer.pub"), "--policy", pol, "--log-key", h.p("log.vkey"))
	if !strings.Contains(out, "[FAIL] subject-digest") {
		t.Fatalf("tampered: %s", out)
	}

	// Monitoring: TOFU, growth, bundle still included.
	out = h.ok("log", "prove", "--server", url, "--log-key", h.p("log.vkey"), "--state", h.p("state"), "--index", "0")
	if !strings.Contains(out, "TOFU") || !strings.Contains(out, "inclusion: entry 0") {
		t.Fatalf("prove: %s", out)
	}
	other := h.write("other.bin", "other")
	h.ok("attest", "--artifact", other, "--key", h.p("signer.key"), "--builder-id", "https://ci.example.test/release@v3",
		"--source-repo", "git+https://git.example.test/acme/app")
	h.ok("log", "submit", "--server", url, "--log-key", h.p("log.vkey"), "--attestation", other+".intoto.json",
		"--pubkey", h.p("signer.pub"), "--out", h.p("other.bundle.json"))
	out = h.ok("log", "prove", "--server", url, "--log-key", h.p("log.vkey"), "--state", h.p("state"),
		"--bundle", h.p("app.bundle.json"))
	if !strings.Contains(out, "size 1 -> 2 verified") || !strings.Contains(out, "is a prefix of the current log") {
		t.Fatalf("prove growth: %s", out)
	}
	out = h.ok("log", "search", "--server", url, "--log-key", h.p("log.vkey"), "--artifact", art)
	if !strings.Contains(out, "1 log entry") {
		t.Fatalf("search: %s", out)
	}
	out = h.ok("log", "search", "--server", url, "--log-key", h.p("log.vkey"), "--artifact", tampered)
	if !strings.Contains(out, "no log entries") {
		t.Fatalf("search miss: %s", out)
	}
	h.ok("log", "checkpoint", "--server", url, "--log-key", h.p("log.vkey"), "--out", h.p("a.cp"))
	out = h.ok("log", "checkpoint", "--server", url, "--log-key", h.p("log.vkey"))
	if !strings.Contains(out, "— log.example.test") {
		t.Fatalf("checkpoint print: %s", out)
	}

	// The operator forks: same key, different history, served elsewhere.
	forkURL := h.startServe(h.p("fork"))
	for _, name := range []string{"f1.bin", "f2.bin", "f3.bin"} {
		f := h.write(name, name)
		h.ok("attest", "--artifact", f, "--key", h.p("signer.key"), "--builder-id", "https://evil.example.test",
			"--source-repo", "git+https://git.example.test/evil/app")
		h.ok("log", "submit", "--server", forkURL, "--log-key", h.p("log.vkey"), "--attestation", f+".intoto.json",
			"--pubkey", h.p("signer.pub"), "--out", h.p(name+".bundle.json"))
	}
	out = h.fails(ExitMisbehaving, "log", "prove", "--server", forkURL, "--log-key", h.p("log.vkey"),
		"--state", h.p("state"), "--evidence-out", h.p("evidence.json"))
	if !strings.Contains(out, "inconsistent") {
		t.Fatalf("fork: %s", out)
	}
	out = h.ok("log", "evidence", "--log-key", h.p("log.vkey"), "--file", h.p("evidence.json"))
	if !strings.Contains(out, "evidence VERIFIED") {
		t.Fatalf("evidence: %s", out)
	}
	h.ok("log", "checkpoint", "--server", forkURL, "--log-key", h.p("log.vkey"), "--out", h.p("b.cp"))
	out = h.fails(ExitMisbehaving, "log", "compare", "--log-key", h.p("log.vkey"), "--a", h.p("a.cp"), "--b", h.p("b.cp"),
		"--server", forkURL, "--evidence-out", h.p("gossip.json"))
	if !strings.Contains(out, "misbehaved") {
		t.Fatalf("compare: %s", out)
	}
	out = h.ok("log", "compare", "--log-key", h.p("log.vkey"), "--a", h.p("a.cp"), "--b", h.p("a.cp"))
	if !strings.Contains(out, "consistent") {
		t.Fatalf("compare same: %s", out)
	}
	// A fork bundle whose checkpoint is ahead of the honest log cannot be
	// proven against it: verification fails (not proof of misbehaviour).
	out = h.fails(ExitFailed, "log", "prove", "--server", url, "--log-key", h.p("log.vkey"), "--bundle", h.p("f3.bin.bundle.json"))
	if !strings.Contains(out, "consistency proof 2->3") {
		t.Fatalf("fork bundle: %s", out)
	}
	h.write("bogus-evidence.json", `{"kind":"equivocation","checkpointA":"x","checkpointB":"y"}`)
	h.fails(ExitFailed, "log", "evidence", "--log-key", h.p("log.vkey"), "--file", h.p("bogus-evidence.json"))
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	cases := [][]string{
		{},
		{"bogus"},
		{"log"},
		{"log", "bogus"},
		{"keygen"},
		{"keygen", "--out", h.p("k"), "--alg", "rsa"},
		{"keygen", "--nope"},
		{"keygen", "--out", h.p("k"), "extra"},
		{"attest"},
		{"verify"},
		{"inspect"},
		{"inspect", "--attestation", "a", "--bundle", "b"},
		{"log", "keygen", "--origin", "bad name", "--out", h.p("l")},
		{"log", "serve"},
		{"log", "submit"},
		{"log", "prove"},
		{"log", "prove", "--server", "http://x", "--log-key", "k", "--index", "1", "--bundle", "b"},
		{"log", "checkpoint"},
		{"log", "compare"},
		{"log", "evidence"},
		{"log", "search"},
		{"log", "serve", "--data", h.p("d"), "--key", "k", "--log-level", "loud"},
	}
	for _, args := range cases {
		if code, _, _ := h.run(args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
	}
	for _, args := range [][]string{{"help"}, {"version"}, {"keygen", "-h"}} {
		if code, _, _ := h.run(args...); code != ExitOK {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestAttestInputErrors(t *testing.T) {
	h := newHarness(t)
	h.ok("keygen", "--out", h.p("k"))
	art := h.write("a.bin", "x")
	base := []string{"attest", "--artifact", art, "--key", h.p("k.key"), "--builder-id", "https://b", "--source-repo", "git+https://r"}
	for _, extra := range [][]string{
		{"--source-digest", "nope"},
		{"--param", "novalue"},
		{"--started-on", "yesterday"},
		{"--finished-on", "tomorrow"},
	} {
		if code, _, _ := h.run(append(append([]string{}, base...), extra...)...); code != ExitUsage {
			t.Errorf("%v: exit %d", extra, code)
		}
	}
	failures := [][]string{
		{"attest", "--artifact", h.p("missing"), "--key", h.p("k.key"), "--builder-id", "https://b", "--source-repo", "r"},
		{"attest", "--artifact", art, "--key", h.p("missing.key"), "--builder-id", "https://b", "--source-repo", "r"},
		{"attest", "--artifact", art, "--key", h.p("k.pub"), "--builder-id", "https://b", "--source-repo", "r"},
		{"attest", "--artifact", art, "--key", h.p("k.key"), "--builder-id", "relative", "--source-repo", "r"},
		append(append([]string{}, base...), "--param", "source=x"),
		{"verify", "--artifact", art, "--attestation", h.p("missing"), "--pubkey", h.p("k.pub"), "--policy", "p"},
		{"verify", "--artifact", art, "--bundle", h.p("missing"), "--pubkey", h.p("k.pub"), "--policy", "p"},
		{"inspect", "--attestation", art},
		{"log", "submit", "--server", "http://127.0.0.1:1", "--log-key", h.p("missing"), "--attestation", "a", "--pubkey", "p", "--out", "o"},
		{"log", "evidence", "--log-key", h.p("k.pub"), "--file", "f"},
	}
	for _, args := range failures {
		if code, _, _ := h.run(args...); code != ExitFailed {
			t.Errorf("%v: exit %d, want %d", args, code, ExitFailed)
		}
	}
	h.ok(base...)
	if code, _, _ := h.run(base...); code != ExitFailed {
		t.Error("attest clobbered existing output")
	}
	pol := h.write("p.json", testPolicy)
	if code, _, _ := h.run("verify", "--artifact", art, "--attestation", art+".intoto.json", "--pubkey", h.p("missing.pub"), "--policy", pol); code != ExitFailed {
		t.Error("missing pubkey accepted")
	}
	if code, _, _ := h.run("verify", "--artifact", art, "--attestation", art+".intoto.json", "--pubkey", h.p("k.pub"), "--policy", h.p("missing")); code != ExitFailed {
		t.Error("missing policy accepted")
	}
	if code, _, _ := h.run("verify", "--artifact", art, "--attestation", art+".intoto.json", "--pubkey", h.p("k.pub"), "--policy", pol, "--log-key", h.p("missing")); code != ExitFailed {
		t.Error("missing log key accepted")
	}
}
