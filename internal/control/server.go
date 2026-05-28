package control

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	store   *Store
	cfg     Config
	logger  *slog.Logger
	mux     *http.ServeMux
	metrics *ControlMetrics
	prom    *PrometheusClient
}

func NewServer(store *Store, cfg Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	metrics, err := NewControlMetrics()
	if err != nil {
		logger.Warn("control metrics disabled", "error", err)
	}
	if store != nil {
		store.metrics = metrics
	}
	s := &Server{store: store, cfg: cfg, logger: logger, mux: http.NewServeMux(), metrics: metrics, prom: NewPrometheusClient(cfg.PrometheusURL, metrics)}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	mw := &metricResponseWriter{ResponseWriter: w, status: http.StatusOK}
	s.mux.ServeHTTP(mw, r)
	if s.metrics != nil {
		s.metrics.ObserveHTTP(r.Method, routeName(r), mw.status, time.Since(start))
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("/v1/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/v1/me", s.handleMe)
	s.mux.HandleFunc("/v1/users", s.handleUsers)
	s.mux.HandleFunc("/v1/users/", s.handleUserByID)
	s.mux.HandleFunc("/v1/services", s.handleServices)
	s.mux.HandleFunc("/v1/services/", s.handleServiceByID)
	s.mux.HandleFunc("/v1/forwarding-policies", s.handleForwardingPolicies)
	s.mux.HandleFunc("/v1/whitelist", s.handleWhitelist)
	s.mux.HandleFunc("/v1/rules", s.handleRules)
	s.mux.HandleFunc("/v1/blacklist", s.handleBlacklist)
	s.mux.HandleFunc("/v1/feed-sources", s.handleFeedSources)
	s.mux.HandleFunc("/v1/feed-sources/", s.handleFeedSourceByID)
	s.mux.HandleFunc("/v1/feed-runs", s.handleFeedRuns)
	s.mux.HandleFunc("/v1/feed-conflicts", s.handleFeedConflicts)
	s.mux.HandleFunc("/v1/telegram/config", s.handleTelegramConfig)
	s.mux.HandleFunc("/v1/telegram/test", s.handleTelegramTest)
	s.mux.HandleFunc("/v1/alerts", s.handleAlerts)
	s.mux.HandleFunc("/v1/alerts/", s.handleAlertSubroute)
	s.mux.HandleFunc("/v1/snapshots", s.handleSnapshots)
	s.mux.HandleFunc("/v1/snapshots/build", s.handleBuildSnapshot)
	s.mux.HandleFunc("/v1/snapshots/rollback", s.handleRollback)
	s.mux.HandleFunc("/v1/audit", s.handleAudit)
	s.mux.HandleFunc("/v1/security-events", s.handleSecurityEvents)
	s.mux.HandleFunc("/v1/security-events/summary", s.handleSecurityEventSummary)
	s.mux.HandleFunc("/v1/security-events/investigate", s.handleSecurityEventInvestigate)
	s.mux.HandleFunc("/v1/baselines", s.handleBaselines)
	s.mux.HandleFunc("/v1/baselines/", s.handleBaselineByID)
	s.mux.HandleFunc("/v1/anomalies", s.handleAnomalies)
	s.mux.HandleFunc("/v1/anomalies/evaluate", s.handleAnomalyEvaluate)
	s.mux.HandleFunc("/v1/dashboard/overview", s.handleDashboardOverview)
	s.mux.HandleFunc("/v1/dashboard/agents", s.handleDashboardAgents)
	s.mux.HandleFunc("/v1/dashboard/services", s.handleDashboardServices)
	s.mux.HandleFunc("/v1/dashboard/rules", s.handleDashboardRules)
	s.mux.HandleFunc("/v1/agents/register", s.handleAgentRegister)
	s.mux.HandleFunc("/v1/agents/", s.handleAgentSubroute)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if s.metrics == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("metrics disabled"))
		return
	}
	ctx, cancel := contextWithTimeout(r, 2*time.Second)
	defer cancel()
	if err := s.store.RefreshControlMetrics(ctx, s.metrics, s.cfg.AgentStaleAfter); err != nil {
		s.logger.Warn("control metrics refresh failed", "error", err)
	}
	promhttp.HandlerFor(s.metrics.Registry(), promhttp.HandlerOpts{Registry: s.metrics.Registry()}).ServeHTTP(w, r)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	session, err := s.store.Authenticate(r.Context(), req.Username, req.Password, s.cfg.SessionTTL)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "anti_ddos_session",
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	token := bearerToken(r)
	if token == "" {
		if cookie, err := r.Cookie("anti_ddos_session"); err == nil {
			token = cookie.Value
		}
	}
	if token != "" {
		_ = s.store.RevokeToken(r.Context(), token)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, actor.User)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := s.store.ListUsers(r.Context())
		writeResult(w, users, err)
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Reason   string `json:"reason"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		user, err := s.store.CreateUser(r.Context(), actor, req.Username, req.Password, req.Role, mutationReason(r.Header.Get("X-Audit-Reason"), req.Reason))
		writeResult(w, user, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/users/")
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	user, err := s.store.RevokeUser(r.Context(), actor, id, r.Header.Get("X-Audit-Reason"))
	writeResult(w, user, err)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		services, err := s.store.ListServices(r.Context())
		writeResult(w, services, err)
	case http.MethodPost:
		var req ServiceInput
		if !decodeJSON(w, r, &req) {
			return
		}
		service, err := s.store.CreateService(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, service, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleServiceByID(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/services/")
	switch r.Method {
	case http.MethodPut:
		var req ServiceInput
		if !decodeJSON(w, r, &req) {
			return
		}
		service, err := s.store.UpdateService(r.Context(), actor, id, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, service, err)
	case http.MethodDelete:
		service, err := s.store.DeleteService(r.Context(), actor, id, r.Header.Get("X-Audit-Reason"))
		writeResult(w, service, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleForwardingPolicies(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		policies, err := s.store.ListForwardingPolicies(r.Context())
		writeResult(w, policies, err)
	case http.MethodPost:
		var req ForwardingPolicyInput
		if !decodeJSON(w, r, &req) {
			return
		}
		policy, err := s.store.CreateForwardingPolicy(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, policy, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		entries, err := s.store.ListWhitelistEntries(r.Context())
		writeResult(w, entries, err)
	case http.MethodPost:
		var req WhitelistInput
		if !decodeJSON(w, r, &req) {
			return
		}
		entry, err := s.store.CreateWhitelistEntry(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, entry, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, err := s.store.ListRules(r.Context())
		writeResult(w, rules, err)
	case http.MethodPost:
		var req RuleInput
		if !decodeJSON(w, r, &req) {
			return
		}
		rule, err := s.store.CreateRule(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, rule, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		entries, err := s.store.ListBlacklistEntries(r.Context())
		writeResult(w, entries, err)
	case http.MethodPost:
		var req BlacklistInput
		if !decodeJSON(w, r, &req) {
			return
		}
		entry, err := s.store.CreateBlacklistEntry(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, entry, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFeedSources(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		sources, err := s.store.ListFeedSources(r.Context())
		writeResult(w, sources, err)
	case http.MethodPost:
		var req FeedSourceInput
		if !decodeJSON(w, r, &req) {
			return
		}
		source, err := s.store.CreateFeedSource(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, source, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFeedSourceByID(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/feed-sources/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeError(w, http.StatusNotFound, errors.New("feed source not found"))
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "sync" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if err := requireOperator(actor); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if r.Body != nil && r.ContentLength != 0 && !decodeJSON(w, r, &req) {
			return
		}
		run, err := s.store.SyncFeedSource(r.Context(), id, actor, mutationReason(r.Header.Get("X-Audit-Reason"), req.Reason))
		writeResult(w, run, err)
		return
	}
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, errors.New("feed source route not found"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		source, err := s.store.GetFeedSource(r.Context(), id)
		writeResult(w, source, err)
	case http.MethodPatch:
		var req FeedSourceInput
		if !decodeJSON(w, r, &req) {
			return
		}
		source, err := s.store.UpdateFeedSource(r.Context(), actor, id, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, source, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFeedRuns(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.store.ListFeedRuns(r.Context(), limit)
	writeResult(w, runs, err)
}

func (s *Server) handleFeedConflicts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	conflicts, err := s.store.ListFeedConflicts(r.Context())
	writeResult(w, conflicts, err)
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	include := r.URL.Query().Get("include_snapshot") == "true"
	snapshots, err := s.store.ListSnapshots(r.Context(), include)
	writeResult(w, snapshots, err)
}

func (s *Server) handleBuildSnapshot(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	meta, err := s.store.RebuildSnapshot(r.Context(), actor, mutationReason(r.Header.Get("X-Audit-Reason"), req.Reason))
	if meta == nil && err == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "unchanged"})
		return
	}
	writeResult(w, meta, err)
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req RollbackRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	meta, err := s.store.RollbackSnapshot(r.Context(), actor, req.TargetVersion, mutationReason(r.Header.Get("X-Audit-Reason"), req.Reason))
	writeResult(w, meta, err)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	writeResult(w, events, err)
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgent(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req AgentRegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	resp, err := s.store.RegisterAgent(r.Context(), req)
	writeResult(w, resp, err)
}

func (s *Server) handleAgentSubroute(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgent(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/agents/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	agentID, action := parts[0], parts[1]
	switch action {
	case "heartbeat":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var req AgentHeartbeatRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp, err := s.store.HeartbeatAgent(r.Context(), agentID, req)
		writeResult(w, resp, err)
	case "snapshot":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		active, _ := strconv.ParseUint(r.URL.Query().Get("active_version"), 10, 32)
		snapshot, err := s.store.FetchSnapshot(r.Context(), uint32(active))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if snapshot == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshot": snapshot})
	case "apply":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var req AgentApplyRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		err := s.store.RecordAgentApply(r.Context(), agentID, req)
		writeResult(w, map[string]bool{"ok": true}, err)
	case "events":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var req SecurityEventBatch
		if !decodeJSON(w, r, &req) {
			if s.metrics != nil {
				s.metrics.IncSecurityEventReject("decode")
			}
			return
		}
		result, err := s.store.IngestSecurityEvents(r.Context(), agentID, req, s.metrics)
		writeResult(w, result, err)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) requireActor(w http.ResponseWriter, r *http.Request) (*Actor, bool) {
	token := bearerToken(r)
	if token == "" {
		if cookie, err := r.Cookie("anti_ddos_session"); err == nil {
			token = cookie.Value
		}
	}
	actor, err := s.store.AuthenticateToken(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return nil, false
	}
	return actor, true
}

func (s *Server) requireAgent(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AgentSharedToken == "" {
		return true
	}
	if bearerToken(r) != s.cfg.AgentSharedToken {
		writeError(w, http.StatusUnauthorized, errors.New("invalid agent token"))
		return false
	}
	return true
}

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[len("Bearer "):])
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeResult(w http.ResponseWriter, value any, err error) {
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "required") && strings.Contains(err.Error(), "role") {
			status = http.StatusForbidden
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

func routeName(r *http.Request) string {
	path := r.URL.Path
	switch {
	case path == "/metrics":
		return "/metrics"
	case path == "/healthz":
		return "/healthz"
	case path == "/v1/auth/login":
		return "/v1/auth/login"
	case path == "/v1/auth/logout":
		return "/v1/auth/logout"
	case path == "/v1/me":
		return "/v1/me"
	case path == "/v1/users":
		return "/v1/users"
	case strings.HasPrefix(path, "/v1/users/"):
		return "/v1/users/{id}"
	case path == "/v1/services":
		return "/v1/services"
	case strings.HasPrefix(path, "/v1/services/"):
		return "/v1/services/{id}"
	case path == "/v1/forwarding-policies":
		return "/v1/forwarding-policies"
	case path == "/v1/whitelist":
		return "/v1/whitelist"
	case path == "/v1/rules":
		return "/v1/rules"
	case path == "/v1/blacklist":
		return "/v1/blacklist"
	case path == "/v1/feed-sources":
		return "/v1/feed-sources"
	case strings.HasPrefix(path, "/v1/feed-sources/"):
		if strings.HasSuffix(path, "/sync") {
			return "/v1/feed-sources/{id}/sync"
		}
		return "/v1/feed-sources/{id}"
	case path == "/v1/feed-runs":
		return "/v1/feed-runs"
	case path == "/v1/feed-conflicts":
		return "/v1/feed-conflicts"
	case path == "/v1/telegram/config":
		return "/v1/telegram/config"
	case path == "/v1/telegram/test":
		return "/v1/telegram/test"
	case path == "/v1/alerts":
		return "/v1/alerts"
	case strings.HasPrefix(path, "/v1/alerts/"):
		if strings.HasSuffix(path, "/evaluate-isp-escalation") {
			return "/v1/alerts/evaluate-isp-escalation"
		}
		if strings.HasSuffix(path, "/deliveries") {
			return "/v1/alerts/{id}/deliveries"
		}
		return "/v1/alerts/{id}"
	case strings.HasPrefix(path, "/v1/snapshots"):
		return "/v1/snapshots"
	case path == "/v1/audit":
		return "/v1/audit"
	case strings.HasPrefix(path, "/v1/security-events"):
		return "/v1/security-events"
	case path == "/v1/baselines":
		return "/v1/baselines"
	case strings.HasPrefix(path, "/v1/baselines/"):
		return "/v1/baselines/{id}"
	case strings.HasPrefix(path, "/v1/anomalies"):
		return "/v1/anomalies"
	case strings.HasPrefix(path, "/v1/dashboard"):
		return "/v1/dashboard"
	case path == "/v1/agents/register":
		return "/v1/agents/register"
	case strings.HasPrefix(path, "/v1/agents/"):
		parts := strings.Split(strings.TrimPrefix(path, "/v1/agents/"), "/")
		if len(parts) == 2 && parts[1] != "" {
			return "/v1/agents/{id}/" + parts[1]
		}
		return "/v1/agents/{id}"
	default:
		return "unknown"
	}
}

func NewHTTPServer(store *Store, cfg Config, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           NewServer(store, cfg, logger),
		ReadHeaderTimeout: 5 * time.Second,
	}
}
