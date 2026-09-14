package migrations

import "embed"

// Files contains the versioned SQL schema consumed by the standalone migrator.
//
//go:embed *.sql
var Files embed.FS

const CurrentVersion int64 = 3
