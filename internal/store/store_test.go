package store

import (
	"testing"
	"time"
)

func TestChallengeMatchesBindsRequestAndIsSingleUse(t *testing.T) {
	now := time.Unix(100, 0)
	c := Challenge{NonceHash: "nonce", RequestID: "request-a", Subject: "reviewer", Decision: "approved", Reason: "ship", ExpiresAt: now.Add(time.Minute)}
	if challengeMatches(c, "request-b", "reviewer", "approved", "ship", now) {
		t.Fatal("challenge for request A authorized request B")
	}
	if !challengeMatches(c, "request-a", "reviewer", "approved", "ship", now) {
		t.Fatal("matching challenge was rejected")
	}
	consumed := now
	c.ConsumedAt = &consumed
	if challengeMatches(c, "request-a", "reviewer", "approved", "ship", now) {
		t.Fatal("consumed challenge was reusable")
	}
}
