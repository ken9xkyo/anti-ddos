package control

import (
	"context"
	"time"
)

const (
	ruleExpiryInterval    = 30 * time.Second
	feedSchedulerInterval = 30 * time.Second
)

func (s *Server) StartBackgroundSchedulers(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	go s.runRuleExpiryScheduler(ctx)
	go s.runFeedScheduler(ctx)
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

func (s *Server) runFeedScheduler(ctx context.Context) {
	ticker := time.NewTicker(feedSchedulerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.store.SyncDueFeeds(ctx); err != nil {
				s.logger.Warn("scheduled feed sync failed", "error", err)
			}
		}
	}
}
