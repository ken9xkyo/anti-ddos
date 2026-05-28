package control

import (
	"context"
	"time"
)

const (
	anomalyEvaluateInterval = 10 * time.Second
	ruleExpiryInterval      = 30 * time.Second
)

func (s *Server) StartBackgroundSchedulers(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	go s.runAnomalyScheduler(ctx)
	go s.runRuleExpiryScheduler(ctx)
}

func (s *Server) runAnomalyScheduler(ctx context.Context) {
	ticker := time.NewTicker(anomalyEvaluateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.store.EvaluateAnomalies(ctx, s.prom, "scheduled anomaly evaluation"); err != nil {
				s.logger.Warn("scheduled anomaly evaluation failed", "error", err)
			}
		}
	}
}

func (s *Server) runRuleExpiryScheduler(ctx context.Context) {
	ticker := time.NewTicker(ruleExpiryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.store.ExpireTTLRules(ctx); err != nil {
				s.logger.Warn("scheduled rule expiry failed", "error", err)
			}
		}
	}
}
