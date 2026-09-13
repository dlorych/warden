package source

import (
	"context"
	"errors"
)

// Event is the source-neutral, immutable deployment request normalized by an adapter.
type Event struct {
	ID, Repository, Environment, CommitSHA, Requester, RequesterSubject string
	Context                                                             []byte
}

var (
	ErrInvalidSignature = errors.New("invalid source signature")
	ErrIgnored          = errors.New("ignored source event")
	ErrMalformed        = errors.New("malformed source event")
	ErrUpstream         = errors.New("source enrichment failed")
)

type Adapter interface {
	Webhook(ctx context.Context, raw []byte, signature string) (Event, error)
	Recheck(ctx context.Context, e Event) (eligible bool, err error)
	Deliver(ctx context.Context, e Event, decision, comment string) error
}
