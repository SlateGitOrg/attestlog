// Package verify is the end-to-end verification pipeline:
//
//  1. authenticate the DSSE envelope with the caller's trusted keys
//  2. parse the in-toto statement (only after authentication)
//  3. optionally verify the transparency-log receipt offline
//  4. evaluate the policy (builder, source, subject digest, threshold, log)
//
// The payload of an envelope that fails authentication is never parsed or
// evaluated, so an attacker cannot influence the report with unsigned data.
package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/archit2501/attestlog/pkg/bundle"
	"github.com/archit2501/attestlog/pkg/checkpoint"
	"github.com/archit2501/attestlog/pkg/dsse"
	"github.com/archit2501/attestlog/pkg/intoto"
	"github.com/archit2501/attestlog/pkg/keys"
	"github.com/archit2501/attestlog/pkg/note"
	"github.com/archit2501/attestlog/pkg/policy"
)

// Request holds everything needed for a verification.
type Request struct {
	Envelope       *dsse.Envelope
	TrustedKeys    []*keys.PublicKey
	ArtifactDigest intoto.DigestSet
	Policy         *policy.Policy
	// Bundle optionally carries a log receipt for Envelope.
	Bundle *bundle.Bundle
	// LogKey verifies the receipt's checkpoint; required with a receipt.
	LogKey *note.Verifier
}

// Result is the outcome of a verification.
type Result struct {
	Report       *policy.Report
	Statement    *intoto.Statement
	SignerKeyIDs []string
	Checkpoint   *checkpoint.Signed
}

// Passed reports whether every check passed.
func (r *Result) Passed() bool { return r.Report != nil && r.Report.Passed }

// Verify runs the pipeline. It returns an error only for unusable input
// (missing policy, keys or envelope); verification failures are reported in
// Result.Report with Passed=false.
func Verify(req Request) (*Result, error) {
	if req.Envelope == nil {
		return nil, errors.New("verify: envelope is required")
	}
	if req.Policy == nil {
		return nil, errors.New("verify: policy is required")
	}
	if err := req.Policy.Validate(); err != nil {
		return nil, err
	}
	if len(req.TrustedKeys) == 0 {
		return nil, errors.New("verify: at least one trusted key is required")
	}
	res := &Result{Report: &policy.Report{}}

	v, err := req.Envelope.Verify(1, req.TrustedKeys...)
	if err != nil {
		res.Report.Checks = append(res.Report.Checks, policy.Check{
			Name: "signature", Passed: false,
			Detail: fmt.Sprintf("no valid signature from a trusted key: %v", err),
		})
		return res, nil
	}
	res.SignerKeyIDs = v.AcceptedKeys
	if req.Envelope.PayloadType != intoto.PayloadType {
		res.Report.Checks = append(res.Report.Checks, policy.Check{
			Name: "payload-type", Passed: false,
			Detail: fmt.Sprintf("payloadType %q, want %q", req.Envelope.PayloadType, intoto.PayloadType),
		})
		return res, nil
	}
	st, err := intoto.ParseStatement(v.Payload)
	if err != nil {
		res.Report.Checks = append(res.Report.Checks, policy.Check{Name: "statement", Passed: false, Detail: err.Error()})
		return res, nil
	}
	res.Statement = st

	var logEv *policy.LogEvidence
	if req.Bundle != nil && req.Bundle.Log != nil {
		logEv = &policy.LogEvidence{Index: req.Bundle.Log.LogIndex}
		switch {
		case req.LogKey == nil:
			logEv.Err = "bundle has a log receipt but no log key was supplied"
		case !sameEnvelope(req.Envelope, &req.Bundle.Envelope):
			logEv.Err = "bundle envelope differs from the attestation being verified"
		default:
			cp, err := req.Bundle.VerifyInclusion(req.LogKey)
			if err != nil {
				logEv.Err = err.Error()
			} else {
				res.Checkpoint = cp
				logEv.Verified, logEv.TreeSize, logEv.Origin = true, cp.Size, cp.Origin
			}
		}
	}

	report := req.Policy.Evaluate(policy.Input{
		Statement:       st,
		ArtifactDigest:  req.ArtifactDigest,
		SignerKeyIDs:    v.AcceptedKeys,
		TransparencyLog: logEv,
	})
	res.Report = report
	return res, nil
}

func sameEnvelope(a, b *dsse.Envelope) bool {
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(ja, jb)
}
