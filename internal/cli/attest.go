package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/archit2501/attestlog/pkg/bundle"
	"github.com/archit2501/attestlog/pkg/dsse"
	"github.com/archit2501/attestlog/pkg/intoto"
	"github.com/archit2501/attestlog/pkg/keys"
	"github.com/archit2501/attestlog/pkg/policy"
	"github.com/archit2501/attestlog/pkg/slsa"
	"github.com/archit2501/attestlog/pkg/verify"
)

func cmdKeygen(e *env, args []string) error {
	fs := newFlags(e, "keygen")
	alg := fs.String("alg", "ed25519", "key algorithm: ed25519 or ecdsa-p256")
	out := fs.String("out", "", "output prefix; writes PREFIX.key and PREFIX.pub")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "out"); err != nil {
		return err
	}
	a, err := keys.ParseAlgorithm(*alg)
	if err != nil {
		return usagef("keygen: %v", err)
	}
	s, err := keys.Generate(a, nil)
	if err != nil {
		return err
	}
	priv, err := keys.MarshalPrivatePEM(s)
	if err != nil {
		return err
	}
	if err := writeFile(*out+".key", priv, 0o600, *force); err != nil {
		return err
	}
	if err := writeFile(*out+".pub", s.Public().MarshalPEM(), 0o644, *force); err != nil {
		return err
	}
	e.printf("generated %s key %s\n  private: %s.key\n  public:  %s.pub\n", a, s.Public().KeyID()[:16], *out, *out)
	return nil
}

func loadSigners(paths []string) ([]keys.Signer, error) {
	out := make([]keys.Signer, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read signing key: %w", err)
		}
		s, err := keys.ParsePrivatePEM(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, s)
	}
	return out, nil
}

func digestFile(path string) (intoto.DigestSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	defer func() { _ = f.Close() }()
	return intoto.DigestReader(f)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, usagef("time %q must be RFC 3339", s)
	}
	return t, nil
}

func cmdAttest(e *env, args []string) error {
	fs := newFlags(e, "attest")
	artifact := fs.String("artifact", "", "artifact file to attest (the in-toto subject)")
	name := fs.String("name", "", "subject name (default: artifact file name)")
	var keyPaths, params multi
	fs.Var(&keyPaths, "key", "PKCS#8 signing key (repeat for multi-signature)")
	builder := fs.String("builder-id", "", "SLSA builder.id URI")
	buildType := fs.String("build-type", slsa.GenericBuildType, "SLSA buildType URI")
	repo := fs.String("source-repo", "", "source repository URI, e.g. git+https://host/org/repo")
	ref := fs.String("source-ref", "", "source ref, e.g. refs/heads/main")
	srcDigest := fs.String("source-digest", "", "source revision digest, e.g. gitCommit:<40 hex>")
	fs.Var(&params, "param", "external parameter key=value (repeatable)")
	invocation := fs.String("invocation-id", "", "build invocation ID")
	started := fs.String("started-on", "", "build start time (RFC 3339)")
	finished := fs.String("finished-on", "", "build finish time (RFC 3339)")
	out := fs.String("out", "", "output envelope path (default ARTIFACT.intoto.json)")
	force := fs.Bool("force", false, "overwrite existing output")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "artifact", "key", "builder-id", "source-repo"); err != nil {
		return err
	}
	signers, err := loadSigners(keyPaths)
	if err != nil {
		return err
	}
	digest, err := digestFile(*artifact)
	if err != nil {
		return err
	}
	opts := slsa.Options{
		BuilderID: *builder, BuildType: *buildType, SourceURI: *repo, SourceRef: *ref,
		InvocationID: *invocation, Parameters: map[string]string{},
	}
	if *srcDigest != "" {
		if opts.SourceDigest, err = intoto.ParseDigest(*srcDigest); err != nil {
			return usagef("attest: --source-digest: %v", err)
		}
	}
	for _, p := range params {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return usagef("attest: --param %q must be key=value", p)
		}
		opts.Parameters[k] = v
	}
	if opts.StartedOn, err = parseTime(*started); err != nil {
		return err
	}
	if opts.FinishedOn, err = parseTime(*finished); err != nil {
		return err
	}
	prov, err := slsa.New(opts)
	if err != nil {
		return err
	}
	subject := *name
	if subject == "" {
		subject = filepath.Base(*artifact)
	}
	st, err := intoto.NewStatement([]intoto.ResourceDescriptor{{Name: subject, Digest: digest}}, slsa.PredicateType, prov)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode statement: %w", err)
	}
	env, err := dsse.Sign(intoto.PayloadType, payload, signers...)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	path := *out
	if path == "" {
		path = *artifact + ".intoto.json"
	}
	if err := writeFile(path, append(data, '\n'), 0o644, *force); err != nil {
		return err
	}
	e.printf("attested %s\n  subject:   %s sha256:%s\n  builder:   %s\n  source:    %s\n  signed by: %d key(s)\n  envelope:  %s\n",
		*artifact, subject, digest["sha256"], *builder, *repo, len(signers), path)
	return nil
}

// loadAttestation reads an envelope or a bundle; exactly one must be given.
func loadAttestation(envPath, bundlePath string) (*dsse.Envelope, *bundle.Bundle, error) {
	switch {
	case envPath != "" && bundlePath != "":
		return nil, nil, usagef("give --attestation or --bundle, not both")
	case bundlePath != "":
		b, err := bundle.Load(bundlePath)
		if err != nil {
			return nil, nil, err
		}
		return &b.Envelope, b, nil
	case envPath != "":
		data, err := os.ReadFile(envPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read attestation: %w", err)
		}
		env, err := dsse.Parse(data)
		if err != nil {
			return nil, nil, err
		}
		return env, nil, nil
	default:
		return nil, nil, usagef("--attestation or --bundle is required")
	}
}

func cmdVerify(e *env, args []string) error {
	fs := newFlags(e, "verify")
	artifact := fs.String("artifact", "", "artifact file whose digest must match a subject")
	envPath := fs.String("attestation", "", "DSSE envelope file")
	bundlePath := fs.String("bundle", "", "bundle file (envelope + log receipt)")
	var pubPaths multi
	fs.Var(&pubPaths, "pubkey", "trusted signer public key (repeatable)")
	policyPath := fs.String("policy", "", "policy JSON file")
	logKeyPath := fs.String("log-key", "", "transparency log verifier key (needed to check a bundle receipt)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(fs, "artifact", "pubkey", "policy"); err != nil {
		return err
	}
	env, b, err := loadAttestation(*envPath, *bundlePath)
	if err != nil {
		return err
	}
	trusted, err := loadPublicKeys(pubPaths)
	if err != nil {
		return err
	}
	pol, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	digest, err := digestFile(*artifact)
	if err != nil {
		return err
	}
	req := verify.Request{Envelope: env, TrustedKeys: trusted, ArtifactDigest: digest, Policy: pol, Bundle: b}
	if *logKeyPath != "" {
		if req.LogKey, err = loadLogKey(*logKeyPath); err != nil {
			return err
		}
	}
	res, err := verify.Verify(req)
	if err != nil {
		return err
	}
	if *asJSON {
		data, _ := json.MarshalIndent(res.Report, "", "  ")
		e.printf("%s\n", data)
	} else {
		e.printf("verifying %s\n", *artifact)
		for _, c := range res.Report.Checks {
			mark := "PASS"
			if !c.Passed {
				mark = "FAIL"
			}
			e.printf("  [%s] %-20s %s\n", mark, c.Name, c.Detail)
		}
	}
	if !res.Passed() {
		return &exitError{code: ExitFailed, err: fmt.Errorf("verification FAILED")}
	}
	if !*asJSON {
		e.printf("verification PASSED\n")
	}
	return nil
}

func cmdInspect(e *env, args []string) error {
	fs := newFlags(e, "inspect")
	envPath := fs.String("attestation", "", "DSSE envelope file")
	bundlePath := fs.String("bundle", "", "bundle file")
	if err := parse(fs, args); err != nil {
		return err
	}
	env, b, err := loadAttestation(*envPath, *bundlePath)
	if err != nil {
		return err
	}
	payload, err := env.DecodePayload()
	if err != nil {
		return err
	}
	e.printf("payloadType: %s\nsignatures:  %d\n", env.PayloadType, len(env.Signatures))
	for _, s := range env.Signatures {
		e.printf("  keyid %s\n", s.KeyID)
	}
	if b != nil && b.Log != nil {
		e.printf("log receipt: index %d, tree size %d\n", b.Log.LogIndex, b.Log.InclusionProof.TreeSize)
	}
	e.printf("UNVERIFIED payload (run \"attestlog verify\" before trusting it):\n")
	var pretty any
	if err := json.Unmarshal(payload, &pretty); err != nil {
		return fmt.Errorf("payload is not JSON: %w", err)
	}
	data, _ := json.MarshalIndent(pretty, "", "  ")
	e.printf("%s\n", data)
	return nil
}
