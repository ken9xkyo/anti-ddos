// Package api exposes the admin REST API.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	cfg "github.com/anti-ddos/antiddosd/pkg/config"
	m "github.com/anti-ddos/antiddosd/pkg/maps"
)

// Server serves /v1/* admin endpoints.
type Server struct {
	addr  string
	h     *m.Handles
	log   *zap.Logger
	cfg   *cfg.Watcher
}

// New builds a Server.
func New(addr string, h *m.Handles, w *cfg.Watcher, log *zap.Logger) *Server {
	if log == nil { log = zap.NewNop() }
	return &Server{addr: addr, h: h, log: log, cfg: w}
}

// Run starts the HTTP server; blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(10 * time.Second))

	r.Route("/v1", func(r chi.Router) {
		r.Post("/block", s.handleBlockAdd)
		r.Delete("/block", s.handleBlockDel)
		r.Post("/whitelist", s.handleWhitelistAdd)
		r.Delete("/whitelist", s.handleWhitelistDel)
		r.Get("/stats", s.handleStats)
		r.Get("/topn", s.handleTopN)
		r.Get("/config", s.handleGetConfig)
		r.Post("/config", s.handlePostConfig)
		r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	srv := &http.Server{Addr: s.addr, Handler: r, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()

	s.log.Info("admin api listening", zap.String("addr", s.addr))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ---- handlers ----------------------------------------------------------

type cidrReq struct {
	CIDR        string `json:"cidr"`
	TTLSeconds  uint32 `json:"ttl_seconds,omitempty"`
}

func (s *Server) handleBlockAdd(w http.ResponseWriter, r *http.Request) {
	var req cidrReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error()); return
	}
	p, err := netip.ParsePrefix(req.CIDR)
	if err != nil { httpError(w, http.StatusBadRequest, err.Error()); return }
	// TTL is informational: the BPF program currently stores expiry as jiffies
	// but does not enforce expiry; userspace reaper clears expired entries.
	if err := s.h.AddPrefix("block", p, 0); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error()); return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cidr": p.String()})
}

func (s *Server) handleBlockDel(w http.ResponseWriter, r *http.Request) {
	var req cidrReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error()); return
	}
	p, err := netip.ParsePrefix(req.CIDR)
	if err != nil { httpError(w, http.StatusBadRequest, err.Error()); return }
	if err := s.h.DelPrefix("block", p); err != nil {
		httpError(w, http.StatusNotFound, err.Error()); return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	var req cidrReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error()); return
	}
	p, err := netip.ParsePrefix(req.CIDR)
	if err != nil { httpError(w, http.StatusBadRequest, err.Error()); return }
	if err := s.h.AddPrefix("whitelist", p, 0); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error()); return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cidr": p.String()})
}

func (s *Server) handleWhitelistDel(w http.ResponseWriter, r *http.Request) {
	var req cidrReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error()); return
	}
	p, err := netip.ParsePrefix(req.CIDR)
	if err != nil { httpError(w, http.StatusBadRequest, err.Error()); return }
	if err := s.h.DelPrefix("whitelist", p); err != nil {
		httpError(w, http.StatusNotFound, err.Error()); return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.h.ReadStats()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error()); return
	}
	out := make(map[string]uint64, m.StatMax)
	for idx := m.StatIdx(0); idx < m.StatMax; idx++ {
		if name := m.StatNames[idx]; name != "" {
			out[name] = snap[idx]
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTopN(w http.ResponseWriter, r *http.Request) {
	limit := 50
	entries, err := s.h.DumpTopN(limit)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error()); return
	}
	type row struct {
		IP    string `json:"ip"`
		Proto uint8  `json:"proto"`
		Pkts  uint64 `json:"pkts"`
		Bytes uint64 `json:"bytes"`
	}
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		out = append(out, row{IP: e.SrcIP.String(), Proto: e.Proto, Pkts: e.Pkts, Bytes: e.Bytes})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Current())
}

func (s *Server) handlePostConfig(w http.ResponseWriter, r *http.Request) {
	var f cfg.File
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		httpError(w, http.StatusBadRequest, err.Error()); return
	}
	if err := s.cfg.Apply(f); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error()); return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- helpers -----------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}
