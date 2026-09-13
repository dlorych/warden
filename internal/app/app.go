package app

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wardenv/service/internal/auth"
	"github.com/wardenv/service/internal/github"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/internal/store"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

type App struct {
	Config Config
	DB     *pgxpool.Pool
	Store  *store.Store
	Auth   *auth.Service
	Source source.Adapter
	logger *slog.Logger
}

func New(ctx context.Context, cfg Config, logger *slog.Logger) (*App, error) {
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	a := &App{Config: cfg, DB: db, Store: store.New(db), logger: logger}
	a.Auth = auth.New(auth.Config{OIDCIssuer: cfg.OIDCIssuer, OIDCClientID: cfg.OIDCClientID, OIDCClientSecret: cfg.OIDCClientSecret, OIDCRedirectURL: cfg.OIDCRedirectURL, OIDCAudience: cfg.OIDCAudience, OIDCInternalBaseURL: cfg.OIDCInternalBaseURL})
	gh := github.New(cfg.GitHubAPIBaseURL, cfg.GitHubAppID, cfg.GitHubPrivateKey)
	a.Source = gh.AsAdapter(cfg.GitHubWebhookSecret, cfg.GitHubActorSubjects)
	return a, nil
}
func (a *App) StartWorker(ctx context.Context) { a.startWorker(ctx) }
func (a *App) Close() {
	if a.DB != nil {
		a.DB.Close()
	}
}
func (a *App) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(securityHeaders, requestLimit)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	r.Mount("/bff", a.bffRouter())
	r.Mount("/api/v1", a.apiRouter())
	r.Post("/webhooks/github", a.githubWebhook)
	r.Get("/evidence/{id}", a.publicEvidence)
	if dist := os.Getenv("WEB_DIST"); dist != "" {
		files := http.FileServer(http.Dir(dist))
		r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			name := filepath.Join(dist, filepath.Clean(req.URL.Path))
			if req.URL.Path == "/" || req.URL.Path == "" {
				http.ServeFile(w, req, filepath.Join(dist, "index.html"))
				return
			}
			if info, err := os.Stat(name); err == nil && !info.IsDir() {
				files.ServeHTTP(w, req)
				return
			}
			http.ServeFile(w, req, filepath.Join(dist, "index.html"))
		}))
	}
	return r
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}
func requestLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		next.ServeHTTP(w, r)
	})
}
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
