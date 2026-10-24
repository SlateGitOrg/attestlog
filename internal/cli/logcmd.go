package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/archit2501/attestlog/pkg/bundle"
	"github.com/archit2501/attestlog/pkg/checkpoint"
	"github.com/archit2501/attestlog/pkg/client"
	"github.com/archit2501/attestlog/pkg/merkle"
	"github.com/archit2501/attestlog/pkg/monitor"
	"github.com/archit2501/attestlog/pkg/note"
	"github.com/archit2501/attestlog/pkg/server"
	"github.com/archit2501/attestlog/pkg/tlog"
)

func cmdLogKeygen(e *env, args []string) error {
	fs := newFlags(e, "log keygen")
	origin := fs.String("origin", "", "log origin / key name, e.g. log.example.test")
	out := fs.String("out", "", "output prefix; writes PREFIX.key and PREFIX.vkey")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "origin", "out"); err != nil {
		return err
	}
	skey, vkey, err := note.GenerateKey(nil, *origin)
	if err != nil {
		return usagef("log keygen: %v", err)
	}
	if err := writeFile(*out+".key", []byte(skey+"\n"), 0o600, *force); err != nil {
		return err
	}
	if err := writeFile(*out+".vkey", []byte(vkey+"\n"), 0o644, *force); err != nil {
		return err
	}
	e.printf("generated log key for origin %s\n  signer:   %s.key\n  verifier: %s.vkey (%s)\n", *origin, *out, *out, vkey)
	return nil
}

func newLogger(e *env, level string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, usagef("invalid --log-level %q", level)
	}
	return slog.New(slog.NewTextHandler(e.stderr, &slog.HandlerOptions{Level: lv})), nil
}

func cmdLogServe(e *env, args []string) error {
	fs := newFlags(e, "log serve")
	dataDir := fs.String("data", "", "directory for the durable entry store")
	keyPath := fs.String("key", "", "log signing key (PRIVATE+KEY+... file)")
	addr := fs.String("addr", "127.0.0.1:8088", "listen address (port 0 picks a free port)")
	addrFile := fs.String("addr-file", "", "write the bound address to this file once listening")
	level := fs.String("log-level", "info", "log level: debug, info, warn, error")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "data", "key"); err != nil {
		return err
	}
	logger, err := newLogger(e, *level)
	if err != nil {
		return err
	}
	skey, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read log key: %w", err)
	}
	signer, err := note.NewSigner(string(skey))
	if err != nil {
		return err
	}
	store, err := tlog.OpenFileStore(*dataDir, logger)
	if err != nil {
		return err
	}
	l, err := tlog.New(store, signer, tlog.Options{Logger: logger})
	if err != nil {
		_ = store.Close()
		return err
	}
	defer func() { _ = l.Close() }()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	bound := ln.Addr().String()
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(bound+"\n"), 0o600); err != nil {
			_ = ln.Close()
			return fmt.Errorf("write addr file: %w", err)
		}
	}
	srv := server.New(l, logger).HTTPServer(bound)
	logger.Info("serving", "addr", "http://"+bound, "origin", signer.Name(), "size", l.Size())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-e.ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

func newClient(server, logKeyPath string) (*client.Client, error) {
	v, err := loadLogKey(logKeyPath)
	if err != nil {
		return nil, err
	}
	return client.New(server, v, nil)
}

// misbehaviour maps verification failures of log responses to exit code 3.
func misbehaviour(err error) error {
	var fe *monitor.ForkError
	if errors.Is(err, client.ErrMisbehaviour) || errors.As(err, &fe) {
		return &exitError{code: ExitMisbehaving, err: err}
	}
	return err
}

func cmdLogSubmit(e *env, args []string) error {
	fs := newFlags(e, "log submit")
	srv := fs.String("server", "", "log server URL")
	logKey := fs.String("log-key", "", "log verifier key file")
	envPath := fs.String("attestation", "", "DSSE envelope to log")
	var pubPaths multi
	fs.Var(&pubPaths, "pubkey", "public key of a signer of the envelope (repeatable)")
	out := fs.String("out", "", "write the bundle (envelope + verified receipt) here")
	force := fs.Bool("force", false, "overwrite existing output")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "server", "log-key", "attestation", "pubkey", "out"); err != nil {
		return err
	}
	c, err := newClient(*srv, *logKey)
	if err != nil {
		return err
	}
	env, _, err := loadAttestation(*envPath, "")
	if err != nil {
		return err
	}
	pubs, err := loadPublicKeys(pubPaths)
	if err != nil {
		return err
	}
	b, dup, err := c.Submit(e.ctx, env, pubs...)
	if err != nil {
		return misbehaviour(err)
	}
	data, err := b.Marshal()
	if err != nil {
		return err
	}
	if err := writeFile(*out, data, 0o644, *force); err != nil {
		return err
	}
	state := "logged"
	if dup {
		state = "already logged"
	}
	e.printf("%s %s\n  log index:  %d\n  tree size:  %d\n  proof:      %d hashes (verified against signed checkpoint)\n  bundle:     %s\n",
		state, *envPath, b.Log.LogIndex, b.Log.InclusionProof.TreeSize, len(b.Log.InclusionProof.Hashes), *out)
	return nil
}

func printCheckpoint(e *env, label string, cp *checkpoint.Signed) {
	ts := "-"
	if !cp.Timestamp.IsZero() {
		ts = cp.Timestamp.Format(time.RFC3339)
	}
	e.printf("%s: origin=%s size=%d root=%s signed=%s\n", label, cp.Origin, cp.Size, cp.Root, ts)
}

func printProof(e *env, hs []merkle.Hash) {
	for i, h := range hs {
		e.printf("    [%d] %s\n", i, h)
	}
}

func saveEvidence(e *env, path string, err error) {
	var fe *monitor.ForkError
	if path == "" || !errors.As(err, &fe) {
		return
	}
	if serr := monitor.SaveEvidence(path, fe.Evidence); serr != nil {
		_, _ = fmt.Fprintf(e.stderr, "attestlog: could not save evidence: %v\n", serr)
		return
	}
	e.printf("evidence written to %s\n", path)
}

func cmdLogProve(e *env, args []string) error {
	fs := newFlags(e, "log prove")
	srv := fs.String("server", "", "log server URL")
	logKey := fs.String("log-key", "", "log verifier key file")
	index := fs.Int64("index", -1, "prove inclusion of the entry at this index")
	bundlePath := fs.String("bundle", "", "prove a bundle's entry is still in the current log")
	statePath := fs.String("state", "", "trusted-checkpoint file; proves consistency and advances it")
	evidenceOut := fs.String("evidence-out", "", "write misbehaviour evidence here if detected")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "server", "log-key"); err != nil {
		return err
	}
	if *index >= 0 && *bundlePath != "" {
		return usagef("log prove: give --index or --bundle, not both")
	}
	c, err := newClient(*srv, *logKey)
	if err != nil {
		return err
	}
	cp, err := c.Checkpoint(e.ctx)
	if err != nil {
		return misbehaviour(err)
	}
	printCheckpoint(e, "checkpoint", cp)

	if *statePath != "" {
		res, err := monitor.Update(e.ctx, monitor.NewState(*statePath), c)
		if err != nil {
			saveEvidence(e, *evidenceOut, err)
			return misbehaviour(err)
		}
		switch {
		case res.FirstUse:
			e.printf("consistency: no trusted state yet; trusting size %d (TOFU) -> %s\n", res.Current.Size, *statePath)
		case res.Stale:
			e.printf("consistency: server returned an older head (size %d < trusted %d, proven consistent: %v); state kept\n",
				res.Current.Size, res.Previous.Size, res.StaleVerified)
		default:
			e.printf("consistency: size %d -> %d verified (append-only); state advanced\n", res.Previous.Size, res.Current.Size)
		}
		cp = res.Current
	}

	switch {
	case *index >= 0:
		idx := uint64(*index)
		_, leaf, err := c.Entry(e.ctx, idx)
		if err != nil {
			return misbehaviour(err)
		}
		proof, err := c.VerifyInclusion(e.ctx, idx, leaf, cp)
		if err != nil {
			return misbehaviour(err)
		}
		e.printf("inclusion: entry %d (leaf %s) is in tree %d — %d-hash proof verified\n", idx, leaf, cp.Size, len(proof))
		printProof(e, proof)
	case *bundlePath != "":
		b, err := bundle.Load(*bundlePath)
		if err != nil {
			return err
		}
		bcp, err := b.VerifyInclusion(c.LogKey())
		if err != nil {
			return &exitError{code: ExitFailed, err: err}
		}
		e.printf("inclusion: bundle entry %d verified offline against its checkpoint (size %d)\n", b.Log.LogIndex, bcp.Size)
		if err := monitor.Compare(e.ctx, bcp, cp, c); err != nil {
			saveEvidence(e, *evidenceOut, err)
			return misbehaviour(err)
		}
		e.printf("consistency: bundle checkpoint (size %d) is a prefix of the current log (size %d)\n", bcp.Size, cp.Size)
	}
	return nil
}

func cmdLogCheckpoint(e *env, args []string) error {
	fs := newFlags(e, "log checkpoint")
	srv := fs.String("server", "", "log server URL")
	logKey := fs.String("log-key", "", "log verifier key file")
	out := fs.String("out", "", "save the signed checkpoint here (for gossip)")
	force := fs.Bool("force", false, "overwrite existing output")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "server", "log-key"); err != nil {
		return err
	}
	c, err := newClient(*srv, *logKey)
	if err != nil {
		return err
	}
	cp, err := c.Checkpoint(e.ctx)
	if err != nil {
		return misbehaviour(err)
	}
	printCheckpoint(e, "checkpoint", cp)
	if *out != "" {
		if err := writeFile(*out, cp.Raw, 0o644, *force); err != nil {
			return err
		}
		e.printf("saved to %s\n", *out)
	} else {
		e.printf("%s", cp.Raw)
	}
	return nil
}

func loadCheckpointFile(path string, v *note.Verifier) (*checkpoint.Signed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	return checkpoint.Open(data, v)
}

func cmdLogCompare(e *env, args []string) error {
	fs := newFlags(e, "log compare")
	logKey := fs.String("log-key", "", "log verifier key file")
	a := fs.String("a", "", "first signed checkpoint file")
	b := fs.String("b", "", "second signed checkpoint file")
	srv := fs.String("server", "", "log server to request a consistency proof from (needed for different sizes)")
	evidenceOut := fs.String("evidence-out", "", "write misbehaviour evidence here if detected")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "log-key", "a", "b"); err != nil {
		return err
	}
	v, err := loadLogKey(*logKey)
	if err != nil {
		return err
	}
	ca, err := loadCheckpointFile(*a, v)
	if err != nil {
		return err
	}
	cb, err := loadCheckpointFile(*b, v)
	if err != nil {
		return err
	}
	printCheckpoint(e, "A", ca)
	printCheckpoint(e, "B", cb)
	var prover monitor.Prover
	if *srv != "" {
		c, err := client.New(*srv, v, nil)
		if err != nil {
			return err
		}
		prover = c
	}
	if err := monitor.Compare(e.ctx, ca, cb, prover); err != nil {
		saveEvidence(e, *evidenceOut, err)
		return misbehaviour(err)
	}
	e.printf("consistent: both checkpoints describe one append-only history\n")
	return nil
}

func cmdLogEvidence(e *env, args []string) error {
	fs := newFlags(e, "log evidence")
	logKey := fs.String("log-key", "", "log verifier key file")
	file := fs.String("file", "", "evidence JSON file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "log-key", "file"); err != nil {
		return err
	}
	v, err := loadLogKey(*logKey)
	if err != nil {
		return err
	}
	ev, err := monitor.LoadEvidence(*file)
	if err != nil {
		return err
	}
	if err := monitor.VerifyEvidence(ev, v); err != nil {
		return &exitError{code: ExitFailed, err: fmt.Errorf("evidence does NOT hold: %w", err)}
	}
	e.printf("evidence VERIFIED: %s by %s\n  %s\n", ev.Kind, ev.Origin, ev.Detail)
	return nil
}

func cmdLogSearch(e *env, args []string) error {
	fs := newFlags(e, "log search")
	srv := fs.String("server", "", "log server URL")
	logKey := fs.String("log-key", "", "log verifier key file")
	artifact := fs.String("artifact", "", "artifact whose attestations to find")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "server", "log-key", "artifact"); err != nil {
		return err
	}
	c, err := newClient(*srv, *logKey)
	if err != nil {
		return err
	}
	d, err := digestFile(*artifact)
	if err != nil {
		return err
	}
	idx, err := c.Search(e.ctx, d)
	if err != nil {
		return err
	}
	if len(idx) == 0 {
		e.printf("no log entries for %s\n", *artifact)
		return nil
	}
	parts := make([]string, len(idx))
	for i, n := range idx {
		parts[i] = fmt.Sprint(n)
	}
	e.printf("%d log entr%s for %s: %s\n", len(idx), plural(len(idx)), *artifact, strings.Join(parts, ", "))
	return nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
