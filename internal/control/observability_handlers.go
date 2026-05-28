package control

import (
	"net/http"
	"time"
)

func (s *Server) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	query, err := parseSecurityEventQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	events, err := s.store.ListSecurityEvents(r.Context(), query)
	writeResult(w, events, err)
}

func (s *Server) handleSecurityEventSummary(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	query, err := parseSecurityEventQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if query.Since.IsZero() {
		query.Since = time.Now().Add(-5 * time.Minute)
	}
	if query.Until.IsZero() {
		query.Until = time.Now()
	}
	summary, err := s.store.SecurityEventSummary(r.Context(), query)
	writeResult(w, summary, err)
}

func (s *Server) handleSecurityEventInvestigate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	result, err := s.store.InvestigateSecurityEvents(r.Context(), r.URL.Query().Get("target"), int(parseUint32Query(r.URL.Query(), "limit")))
	writeResult(w, result, err)
}

func (s *Server) handleDashboardOverview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	overview, err := s.store.BuildDashboardOverview(r.Context(), s.prom, s.cfg.AgentStaleAfter)
	writeResult(w, overview, err)
}

func (s *Server) handleDashboardAgents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	agents, err := s.store.ListDashboardAgents(r.Context(), s.cfg.AgentStaleAfter)
	writeResult(w, agents, err)
}

func (s *Server) handleDashboardServices(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	services, err := s.store.ListDashboardServices(r.Context())
	writeResult(w, services, err)
}

func (s *Server) handleDashboardRules(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	rules, err := s.store.ListDashboardRules(r.Context())
	writeResult(w, rules, err)
}
