// Package cli implements the attestlog command line. Run is the testable
// entry point; cmd/attestlog only wires it to the process.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/SlateGitOrg/attestlog/pkg/keys"
	"github.com/SlateGitOrg/attestlog/pkg/note"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitFailed      = 1 // verification failed or runtime error
	ExitUsage       = 2 // bad flags or arguments
	ExitMisbehaving = 3 // the log was caught misbehaving
)

// Version is overridden at build time with -ldflags.
var Version = "dev"

const usage = `attestlog — SLSA provenance + in-toto attestations with an offline transparency log

Usage:
  attestlog keygen      --alg ed25519|ecdsa-p256 --out PREFIX
  attestlog attest      --artifact FILE --key KEY --builder-id URI --source-repo URI [flags]
  attestlog verify      --artifact FILE (--attestation FILE | --bundle FILE) --pubkey PUB --policy FILE [--log-key VKEY]
  attestlog inspect     (--attestation FILE | --bundle FILE)

  attestlog log keygen     --origin NAME --out PREFIX
  attestlog log serve      --data DIR --key LOGKEY [--addr HOST:PORT] [--addr-file FILE]
  attestlog log submit     --server URL --log-key VKEY --attestation FILE --pubkey PUB --out BUNDLE
  attestlog log prove      --server URL --log-key VKEY [--index N | --bundle FILE] [--state FILE]
  attestlog log checkpoint --server URL --log-key VKEY [--out FILE]
  attestlog log compare    --log-key VKEY --a FILE --b FILE [--server URL]
  attestlog log evidence   --log-key VKEY --file FILE
  attestlog log search     --server URL --log-key VKEY --artifact FILE

Run "attestlog <command> -h" for the flags of a command.
Exit codes: 0 ok, 1 failed, 2 usage error, 3 log misbehaviour detected.
`

// env bundles the I/O streams so commands are testable.
type env struct {
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
}

func (e *env) printf(format string, args ...any) { _, _ = fmt.Fprintf(e.stdout, format, args...) }

// usageError marks errors that should exit with ExitUsage.
type usageError struct{ msg string }

func (u *usageError) Error() string { return u.msg }

func usagef(format string, args ...any) error { return &usageError{msg: fmt.Sprintf(format, args...)} }

// exitError carries a specific exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// Run executes the command line args (without the program name).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	e := &env{ctx: ctx, stdout: stdout, stderr: stderr}
	err := dispatch(e, args)
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "attestlog: %v\n", err)
	var ue *usageError
	if errors.As(err, &ue) {
		return ExitUsage
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return ExitFailed
}

func dispatch(e *env, args []string) error {
	if len(args) == 0 {
		_, _ = io.WriteString(e.stderr, usage)
		return usagef("no command given")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "keygen":
		return cmdKeygen(e, rest)
	case "attest":
		return cmdAttest(e, rest)
	case "verify":
		return cmdVerify(e, rest)
	case "inspect":
		return cmdInspect(e, rest)
	case "log":
		return dispatchLog(e, rest)
	case "version", "--version":
		e.printf("attestlog %s\n", Version)
		return nil
	case "help", "-h", "--help":
		_, _ = io.WriteString(e.stdout, usage)
		return nil
	default:
		return usagef("unknown command %q (run \"attestlog help\")", cmd)
	}
}

func dispatchLog(e *env, args []string) error {
	if len(args) == 0 {
		return usagef("log: missing subcommand (keygen, serve, submit, prove, checkpoint, compare, evidence, search)")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "keygen":
		return cmdLogKeygen(e, rest)
	case "serve":
		return cmdLogServe(e, rest)
	case "submit":
		return cmdLogSubmit(e, rest)
	case "prove":
		return cmdLogProve(e, rest)
	case "checkpoint":
		return cmdLogCheckpoint(e, rest)
	case "compare":
		return cmdLogCompare(e, rest)
	case "evidence":
		return cmdLogEvidence(e, rest)
	case "search":
		return cmdLogSearch(e, rest)
	default:
		return usagef("log: unknown subcommand %q", cmd)
	}
}

// newFlags returns a flag set that reports errors instead of exiting.
func newFlags(e *env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usagef("%s: %v", fs.Name(), err)
	}
	if fs.NArg() > 0 {
		return usagef("%s: unexpected arguments %v", fs.Name(), fs.Args())
	}
	return nil
}

func require(fs *flag.FlagSet, names ...string) error {
	for _, n := range names {
		if f := fs.Lookup(n); f == nil || f.Value.String() == "" {
			return usagef("%s: --%s is required", fs.Name(), n)
		}
	}
	return nil
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func loadPublicKeys(paths []string) ([]*keys.PublicKey, error) {
	out := make([]*keys.PublicKey, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read public key: %w", err)
		}
		k, err := keys.ParsePublicPEM(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, k)
	}
	return out, nil
}

func loadLogKey(path string) (*note.Verifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read log key: %w", err)
	}
	v, err := note.NewVerifier(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

// writeFile writes data, refusing to clobber an existing file unless force.
func writeFile(path string, data []byte, mode os.FileMode, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !force {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
