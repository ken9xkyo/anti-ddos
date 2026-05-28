package control

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleTelegramConfig(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, err := s.store.GetTelegramConfig(r.Context())
		writeResult(w, cfg, err)
	case http.MethodPost:
		var req TelegramConfigInput
		if !decodeJSON(w, r, &req) {
			return
		}
		cfg, err := s.store.UpsertTelegramConfig(r.Context(), actor, req, r.Header.Get("X-Audit-Reason"))
		writeResult(w, cfg, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request) {
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
	if r.Body != nil && r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	alert, err := s.store.CreateAlert(r.Context(), actor, AlertInput{
		Severity:          "info",
		Type:              "test_alert",
		DedupeKey:         "test-alert:" + actor.ID,
		AffectedService:   "control-plane",
		Vector:            "operator_test",
		Evidence:          mustJSON(map[string]string{"reason": mutationReason(r.Header.Get("X-Audit-Reason"), req.Reason)}),
		RecommendedAction: "confirm Telegram delivery result",
	})
	writeResult(w, alert, err)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireActor(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		alerts, err := s.store.ListAlerts(r.Context(), limit)
		writeResult(w, alerts, err)
	case http.MethodPost:
		var req AlertInput
		if !decodeJSON(w, r, &req) {
			return
		}
		alert, err := s.store.CreateAlert(r.Context(), actor, req)
		writeResult(w, alert, err)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleAlertSubroute(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireActor(w, r); !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/alerts/")
	if rest == "evaluate-isp-escalation" {
		s.handleISPEscalation(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "deliveries" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	deliveries, err := s.store.ListAlertDeliveries(r.Context(), parts[0])
	writeResult(w, deliveries, err)
}

func (s *Server) handleISPEscalation(w http.ResponseWriter, r *http.Request) {
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
	var req ISPEscalationInput
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.prom != nil && s.prom.Configured() {
		if req.PeakPPS == 0 {
			if value, status := s.prom.QueryScalar(r.Context(), `sum(rate(anti_ddos_xdp_packets_total{action=~"0|1|6"}[1m]))`); status.Healthy {
				req.PeakPPS = value
			}
		}
		if req.PeakBPS == 0 {
			if value, status := s.prom.QueryScalar(r.Context(), `sum(rate(anti_ddos_xdp_bytes_total{action=~"0|1|6"}[1m])) * 8`); status.Healthy {
				req.PeakBPS = value
			}
		}
	}
	alert, err := s.store.EvaluateISPEscalation(r.Context(), actor, req)
	writeResult(w, alert, err)
}
