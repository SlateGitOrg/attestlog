// Package slsa implements the SLSA Provenance v1 predicate.
//
// Spec: https://slsa.dev/spec/v1.0/provenance
package slsa

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/SlateGitOrg/attestlog/pkg/intoto"
)

// PredicateType is the predicateType URI for SLSA Provenance v1.
const PredicateType = "https://slsa.dev/provenance/v1"

// GenericBuildType is the buildType this tool emits. Its externalParameters
// convention is documented in docs/ARCHITECTURE.md: a "source" object with
// "uri", "digest" and optional "ref", plus free-form string parameters.
const GenericBuildType = "https://github.com/SlateGitOrg/attestlog/buildtypes/generic/v1"

// ErrInvalidProvenance wraps every predicate validation failure.
var ErrInvalidProvenance = errors.New("slsa: invalid provenance")

// Provenance is the SLSA v1 provenance predicate.
type Provenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes the inputs of the build.
type BuildDefinition struct {
	BuildType            string                      `json:"buildType"`
	ExternalParameters   map[string]any              `json:"externalParameters"`
	InternalParameters   map[string]any              `json:"internalParameters,omitempty"`
	ResolvedDependencies []intoto.ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// RunDetails describes this particular execution of the build.
type RunDetails struct {
	Builder    Builder                     `json:"builder"`
	Metadata   *BuildMetadata              `json:"metadata,omitempty"`
	Byproducts []intoto.ResourceDescriptor `json:"byproducts,omitempty"`
}

// Builder identifies the trusted build platform.
type Builder struct {
	ID                  string                      `json:"id"`
	Version             map[string]string           `json:"version,omitempty"`
	BuilderDependencies []intoto.ResourceDescriptor `json:"builderDependencies,omitempty"`
}

// BuildMetadata holds timing and invocation information.
type BuildMetadata struct {
	InvocationID string     `json:"invocationId,omitempty"`
	StartedOn    *time.Time `json:"startedOn,omitempty"`
	FinishedOn   *time.Time `json:"finishedOn,omitempty"`
}

// Validate enforces the required fields of the v1 predicate.
func (p *Provenance) Validate() error {
	if err := requireURI("buildDefinition.buildType", p.BuildDefinition.BuildType); err != nil {
		return err
	}
	if p.BuildDefinition.ExternalParameters == nil {
		return fmt.Errorf("%w: buildDefinition.externalParameters is required", ErrInvalidProvenance)
	}
	if err := requireURI("runDetails.builder.id", p.RunDetails.Builder.ID); err != nil {
		return err
	}
	for i := range p.BuildDefinition.ResolvedDependencies {
		if err := p.BuildDefinition.ResolvedDependencies[i].Validate(); err != nil {
			return fmt.Errorf("%w: resolvedDependencies[%d]: %w", ErrInvalidProvenance, i, err)
		}
	}
	if m := p.RunDetails.Metadata; m != nil && m.StartedOn != nil && m.FinishedOn != nil &&
		m.FinishedOn.Before(*m.StartedOn) {
		return fmt.Errorf("%w: finishedOn precedes startedOn", ErrInvalidProvenance)
	}
	return nil
}

func requireURI(field, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidProvenance, field)
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("%w: %s must be an absolute URI, got %q", ErrInvalidProvenance, field, v)
	}
	return nil
}

// Source is the source revision a build claims to have consumed.
type Source struct {
	URI    string
	Ref    string
	Digest intoto.DigestSet
}

// SourceOf extracts the source revision from the provenance. It first reads
// the generic buildType convention (externalParameters.source as an object
// or a string URI), then falls back to the first resolved dependency whose
// URI uses a git scheme. The digest comes from the matching resolved
// dependency when the parameters do not carry one.
func (p *Provenance) SourceOf() (Source, bool) {
	var src Source
	switch v := p.BuildDefinition.ExternalParameters["source"].(type) {
	case string:
		src.URI = v
	case map[string]any:
		if s, ok := v["uri"].(string); ok {
			src.URI = s
		}
		if s, ok := v["ref"].(string); ok {
			src.Ref = s
		}
		if d, ok := v["digest"].(map[string]any); ok {
			src.Digest = intoto.DigestSet{}
			for k, val := range d {
				if s, ok := val.(string); ok {
					src.Digest[k] = s
				}
			}
		}
	}
	deps := p.BuildDefinition.ResolvedDependencies
	if src.URI == "" {
		for _, d := range deps {
			if strings.HasPrefix(d.URI, "git+") {
				src.URI = d.URI
				break
			}
		}
	}
	if src.URI == "" {
		return Source{}, false
	}
	if src.Ref == "" {
		if repo := repoOf(src.URI); repo != src.URI {
			src.Ref = src.URI[len(repo)+1:]
		}
	}
	if len(src.Digest) == 0 {
		for _, d := range deps {
			if repoOf(d.URI) == repoOf(src.URI) && len(d.Digest) > 0 {
				src.Digest = d.Digest
				break
			}
		}
	}
	return src, true
}

// Repo returns the source URI without any "@ref" suffix.
func (s Source) Repo() string { return repoOf(s.URI) }

// repoOf strips an "@ref" suffix. The "@" is only searched for after the
// authority section so that "ssh://git@host/repo" keeps its user-info.
func repoOf(uri string) string {
	pathStart := 0
	if i := strings.Index(uri, "://"); i >= 0 {
		rest := uri[i+3:]
		j := strings.Index(rest, "/")
		if j < 0 {
			return uri
		}
		pathStart = i + 3 + j
	}
	if k := strings.Index(uri[pathStart:], "@"); k >= 0 {
		return uri[:pathStart+k]
	}
	return uri
}

// Options configures New.
type Options struct {
	BuilderID    string
	BuildType    string
	SourceURI    string
	SourceRef    string
	SourceDigest intoto.DigestSet
	Parameters   map[string]string
	InvocationID string
	StartedOn    time.Time
	FinishedOn   time.Time
}

// New builds a provenance predicate following the generic buildType
// convention and validates it.
func New(o Options) (*Provenance, error) {
	ext := map[string]any{}
	for k, v := range o.Parameters {
		if k == "source" {
			return nil, fmt.Errorf("%w: parameter name %q is reserved", ErrInvalidProvenance, k)
		}
		ext[k] = v
	}
	var deps []intoto.ResourceDescriptor
	if o.SourceURI != "" {
		src := map[string]any{"uri": o.SourceURI}
		if o.SourceRef != "" {
			src["ref"] = o.SourceRef
		}
		if len(o.SourceDigest) > 0 {
			if err := o.SourceDigest.Validate(); err != nil {
				return nil, fmt.Errorf("%w: source digest: %w", ErrInvalidProvenance, err)
			}
			d := map[string]any{}
			for k, v := range o.SourceDigest {
				d[k] = v
			}
			src["digest"] = d
			deps = append(deps, intoto.ResourceDescriptor{URI: o.SourceURI, Digest: o.SourceDigest})
		}
		ext["source"] = src
	}
	bt := o.BuildType
	if bt == "" {
		bt = GenericBuildType
	}
	p := &Provenance{
		BuildDefinition: BuildDefinition{
			BuildType:            bt,
			ExternalParameters:   ext,
			ResolvedDependencies: deps,
		},
		RunDetails: RunDetails{Builder: Builder{ID: o.BuilderID}},
	}
	if o.InvocationID != "" || !o.StartedOn.IsZero() || !o.FinishedOn.IsZero() {
		md := &BuildMetadata{InvocationID: o.InvocationID}
		if !o.StartedOn.IsZero() {
			t := o.StartedOn.UTC()
			md.StartedOn = &t
		}
		if !o.FinishedOn.IsZero() {
			t := o.FinishedOn.UTC()
			md.FinishedOn = &t
		}
		p.RunDetails.Metadata = md
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// FromStatement decodes and validates the provenance carried by st.
func FromStatement(st *intoto.Statement) (*Provenance, error) {
	if st.PredicateType != PredicateType {
		return nil, fmt.Errorf("%w: predicateType %q, want %q", ErrInvalidProvenance, st.PredicateType, PredicateType)
	}
	var p Provenance
	if err := st.DecodePredicate(&p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}
