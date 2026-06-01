package control

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		profiles, err := s.store.ListBaselineProfiles(r.Context())
		writeResult(w, profiles, err)
	case http.MethodPost:
		var req BaselineProfileInput
		if !decodeJSON(w, r, &req) {
			return
		}
		profile, err := s.store.CreateBaselineProfile(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, profile, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleBaselineByID(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/baselines/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id, action := parts[0], parts[1]
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	switch action {
	case "approve":
		var req struct {
			Reason string `json:"reason"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		profile, err := s.store.ApproveBaselineProfile(r.Context(), actor, id, mutationReason(r.Header.Get("X-Audit-Reason"), req.Reason))
		writeResult(w, profile, err)
	case "recalibrate":
		var req BaselineProfileInput
		if !decodeJSON(w, r, &req) {
			return
		}
		profile, err := s.store.RecalibrateBaselineProfile(r.Context(), actor, id, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, profile, err)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	anomalies, err := s.store.ListAnomalies(r.Context(), limit)
	writeResult(w, anomalies, err)
}

func (s *Server) handleAnomalyEvaluate(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	if err := requireOperator(actor); err != nil {
		writeError(w, http.StatusForbidden, err)
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
	evaluations, err := s.store.EvaluateAnomalies(r.Context(), s.prom, mutationReason(r.Header.Get("X-Audit-Reason"), req.Reason))
	writeResult(w, evaluations, err)
}
