package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

const (
	feedStatusHealthy                 = "healthy"
	feedStatusError                   = "error"
	feedStatusRunning                 = "running"
	feedCredentialMask                = "***"
	defaultFeedTTL                    = 24 * time.Hour
	maxFeedBodyBytes                  = 16 << 20
	defaultAbuseIPDBConfidenceMinimum = 100
	defaultAbuseIPDBLimit             = 9999999
	defaultAbuseIPDBIPVersion         = 4
)

type normalizedFeedEntry struct {
	CIDR       netip.Prefix
	Score      uint32
	Action     string
	TTLSeconds uint32
	Reason     string
	Metadata   json.RawMessage
}

type parsedFeed struct {
	Fetched     uint32
	ParseErrors uint32
	Entries     []normalizedFeedEntry
}

type internalFeedItem struct {
	IP         string          `json:"ip"`
	CIDR       string          `json:"cidr"`
	Score      uint32          `json:"score"`
	Action     string          `json:"action"`
	TTLSeconds uint32          `json:"ttl_seconds"`
	Reason     string          `json:"reason"`
	Source     json.RawMessage `json:"source_metadata"`
	Metadata   json.RawMessage `json:"metadata"`
}

type feedWhitelist struct {
	ID     string
	Prefix netip.Prefix
}

type conflictMatch struct {
	WhitelistID string
}

func (s *Store) SyncDueFeeds(ctx context.Context) (int, error) {
	tx, err := s.beginContextOrPlatformTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text FROM feed_sources
WHERE enabled
  AND (next_run_at IS NULL OR next_run_at <= now())
ORDER BY COALESCE(next_run_at, now()), name`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type dueFeed struct {
		id       string
		tenantID string
	}
	var feeds []dueFeed
	for rows.Next() {
		var feed dueFeed
		if err := rows.Scan(&feed.id, &feed.tenantID); err != nil {
			return 0, err
		}
		feeds = append(feeds, feed)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	var joined error
	for _, feed := range feeds {
		feedCtx := contextWithTenant(ctx, feed.tenantID)
		if _, err := s.SyncFeedSource(feedCtx, feed.id, nil, "scheduled feed sync"); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return len(feeds), joined
}

func (s *Store) SyncFeedSource(ctx context.Context, sourceID string, actor *Actor, reason string) (FeedRun, error) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return FeedRun{}, errors.New("source id is required")
	}
	lock := s.feedLock(sourceID)
	if !lock.TryLock() {
		return FeedRun{}, errors.New("feed sync already running")
	}
	defer lock.Unlock()

	if tenantIDFromContext(ctx) == "" {
		if tenantIDFromActor := actorTenantID(actor); tenantIDFromActor != "" {
			ctx = contextWithTenant(ctx, tenantIDFromActor)
		} else {
			var err error
			ctx, err = s.tenantContextForFeedSource(ctx, sourceID)
			if err != nil {
				return FeedRun{}, err
			}
		}
	}
	source, err := s.GetFeedSource(ctx, sourceID)
	if err != nil {
		return FeedRun{}, err
	}
	run, err := s.startFeedRun(ctx, source.ID)
	if err != nil {
		return FeedRun{}, err
	}
	body, err := s.fetchFeed(ctx, source)
	if err != nil {
		return s.finishFeedRun(ctx, source, run.ID, nil, 0, 0, 0, err)
	}
	parsed := parseFeedPayload(source, body, time.Now().UTC())
	whitelist, err := s.loadFeedWhitelist(ctx)
	if err != nil {
		return s.finishFeedRun(ctx, source, run.ID, nil, parsed.Fetched, uint32(len(parsed.Entries)), parsed.ParseErrors, err)
	}
	entries := aggregateFeedEntries(dedupeFeedEntries(parsed.Entries), whitelist)
	snapshotVersion, err := s.replaceFeedEntries(ctx, source, entries, whitelist, actor, reason)
	if err != nil {
		return s.finishFeedRun(ctx, source, run.ID, nil, parsed.Fetched, uint32(len(entries)), parsed.ParseErrors, err)
	}
	return s.finishFeedRun(ctx, source, run.ID, &snapshotVersion, parsed.Fetched, uint32(len(entries)), parsed.ParseErrors, nil)
}

func (s *Store) feedLock(sourceID string) *sync.Mutex {
	s.feedMu.Lock()
	defer s.feedMu.Unlock()
	if s.feedLocks == nil {
		s.feedLocks = map[string]*sync.Mutex{}
	}
	lock := s.feedLocks[sourceID]
	if lock == nil {
		lock = &sync.Mutex{}
		s.feedLocks[sourceID] = lock
	}
	return lock
}

func (s *Store) fetchFeed(ctx context.Context, source FeedSource) ([]byte, error) {
	endpoint := strings.TrimSpace(source.URL)
	sourceType := normalizeFeedType(source.Type)
	if endpoint == "" && sourceType == "abuseipdb" {
		endpoint = "https://api.abuseipdb.com/api/v2/blacklist"
	}
	if endpoint == "" {
		return nil, errors.New("feed url is required")
	}
	credential, credentialStatus := resolveCredentialRef(source.CredentialRef)
	switch credentialStatus {
	case "missing":
		return nil, errors.New("feed credential is missing")
	case "invalid":
		return nil, errors.New("feed credential is invalid")
	case "masked":
		return nil, errors.New("feed credential is masked")
	}
	if sourceType == "abuseipdb" && credential == "" {
		return nil, errors.New("abuseipdb key is required")
	}
	requestURL, err := feedRequestURL(source, endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "anti-ddos-feed-sync/phase08")
	switch sourceType {
	case "abuseipdb":
		req.Header.Set("Key", credential)
		req.Header.Set("Accept", "text/plain")
	default:
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
	}
	client := s.feedHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxFeedBodyBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if len(body) > maxFeedBodyBytes {
			return nil, errors.New("feed response exceeds maximum size")
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("feed fetch status %d", resp.StatusCode)
			continue
		}
		return body, nil
	}
	return nil, lastErr
}

func feedRequestURL(source FeedSource, endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if normalizeFeedType(source.Type) == "abuseipdb" {
		q := u.Query()
		if q.Get("plaintext") == "" {
			q.Set("plaintext", "true")
		}
		quota := map[string]any{}
		_ = json.Unmarshal(source.QuotaMetadata, &quota)
		if q.Get("confidenceMinimum") == "" {
			q.Set("confidenceMinimum", fmt.Sprint(intFromQuota(quota, "confidenceMinimum", defaultAbuseIPDBConfidenceMinimum)))
		}
		if q.Get("limit") == "" {
			q.Set("limit", fmt.Sprint(intFromQuota(quota, "limit", defaultAbuseIPDBLimit)))
		}
		if q.Get("ipversion") == "" {
			q.Set("ipversion", fmt.Sprint(intFromQuota(quota, "ipversion", defaultAbuseIPDBIPVersion)))
		}
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

func parseFeedPayload(source FeedSource, body []byte, now time.Time) parsedFeed {
	sourceType := normalizeFeedType(source.Type)
	switch sourceType {
	case "internal_json", "internal":
		return parseInternalJSONFeed(source, body, now)
	default:
		return parsePlainTextFeed(source, body, now)
	}
}

func parsePlainTextFeed(source FeedSource, body []byte, now time.Time) parsedFeed {
	var out parsedFeed
	sourceType := normalizeFeedType(source.Type)
	defaultScore := uint32(100)
	if sourceType == "abuseipdb" {
		defaultScore = uint32(intFromQuota(rawJSONMap(source.QuotaMetadata), "confidenceMinimum", defaultAbuseIPDBConfidenceMinimum))
	}
	defaultTTL := defaultTTLSeconds(source, defaultFeedTTL)
	for _, rawLine := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		out.Fetched++
		reason := ""
		if idx := strings.IndexAny(line, ";#"); idx >= 0 {
			reason = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		prefix, err := parseCIDR(fields[0])
		if err != nil {
			out.ParseErrors++
			continue
		}
		out.Entries = append(out.Entries, normalizedFeedEntry{
			CIDR:       prefix,
			Score:      defaultScore,
			Action:     "drop",
			TTLSeconds: defaultTTL,
			Reason:     reason,
			Metadata:   json.RawMessage(`{}`),
		})
	}
	return out
}

func parseInternalJSONFeed(source FeedSource, body []byte, now time.Time) parsedFeed {
	var payload struct {
		Entries []internalFeedItem `json:"entries"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		var entries []internalFeedItem
		if arrayErr := json.Unmarshal(body, &entries); arrayErr != nil {
			return parsedFeed{Fetched: 1, ParseErrors: 1}
		}
		payload.Entries = entries
	}
	var out parsedFeed
	defaultTTL := defaultTTLSeconds(source, defaultFeedTTL)
	for _, item := range payload.Entries {
		out.Fetched++
		value := item.CIDR
		if strings.TrimSpace(value) == "" {
			value = item.IP
		}
		prefix, err := parseCIDR(value)
		if err != nil {
			out.ParseErrors++
			continue
		}
		score := item.Score
		if score == 0 {
			score = 80
		}
		ttl := item.TTLSeconds
		if ttl == 0 {
			ttl = defaultTTL
		}
		action := normalizeBlacklistAction(item.Action)
		if action != "drop" {
			out.ParseErrors++
			continue
		}
		metadata := item.Metadata
		if len(metadata) == 0 {
			metadata = item.Source
		}
		if len(metadata) == 0 || !json.Valid(metadata) {
			metadata = json.RawMessage(`{}`)
		}
		out.Entries = append(out.Entries, normalizedFeedEntry{
			CIDR:       prefix,
			Score:      score,
			Action:     action,
			TTLSeconds: ttl,
			Reason:     strings.TrimSpace(item.Reason),
			Metadata:   metadata,
		})
	}
	return out
}

func dedupeFeedEntries(entries []normalizedFeedEntry) []normalizedFeedEntry {
	seen := map[string]normalizedFeedEntry{}
	for _, entry := range entries {
		key := fmt.Sprintf("%s|%s|%d|%d", entry.CIDR.String(), entry.Action, entry.Score, entry.TTLSeconds)
		if _, ok := seen[key]; !ok {
			seen[key] = entry
		}
	}
	out := make([]normalizedFeedEntry, 0, len(seen))
	for _, entry := range seen {
		out = append(out, entry)
	}
	sortFeedEntries(out)
	return out
}

func aggregateFeedEntries(entries []normalizedFeedEntry, whitelist []feedWhitelist) []normalizedFeedEntry {
	current := dedupeFeedEntries(entries)
	changed := true
	for changed {
		changed = false
		byPrefix := map[netip.Prefix]normalizedFeedEntry{}
		for _, entry := range current {
			byPrefix[entry.CIDR] = entry
		}
		for bits := 32; bits > 0 && !changed; bits-- {
			sortFeedEntries(current)
			for _, left := range current {
				if left.CIDR.Bits() != bits {
					continue
				}
				rightPrefix, ok := siblingPrefix(left.CIDR)
				if !ok {
					continue
				}
				right, ok := byPrefix[rightPrefix]
				if !ok || !feedMergeCompatible(left, right) {
					continue
				}
				parent, ok := parentPrefix(left.CIDR)
				if !ok || prefixContainsAnyWhitelist(parent, whitelist) {
					continue
				}
				next := make([]normalizedFeedEntry, 0, len(current)-1)
				for _, entry := range current {
					if entry.CIDR == left.CIDR || entry.CIDR == right.CIDR {
						continue
					}
					next = append(next, entry)
				}
				left.CIDR = parent
				next = append(next, left)
				current = next
				changed = true
				break
			}
		}
	}
	sortFeedEntries(current)
	return current
}

func (s *Store) replaceFeedEntries(ctx context.Context, source FeedSource, entries []normalizedFeedEntry, whitelist []feedWhitelist, actor *Actor, reason string) (uint32, error) {
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE reputation_entries SET status='inactive', last_seen_at=now() WHERE source_id=$1`, source.ID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE feed_conflicts SET status='resolved', resolved_at=now() WHERE source_id=$1 AND status='active'`, source.ID); err != nil {
		return 0, err
	}
	var activeEntries, conflicts uint32
	for _, entry := range entries {
		matches := matchingWhitelists(entry.CIDR, whitelist)
		status := "active"
		if len(matches) > 0 {
			status = "suppressed"
			conflicts += uint32(len(matches))
		} else {
			activeEntries++
		}
		var expires any
		if entry.TTLSeconds > 0 {
			expires = time.Now().UTC().Add(time.Duration(entry.TTLSeconds) * time.Second)
		}
		entryID, err := newUUID()
		if err != nil {
			return 0, err
		}
		var reputationID string
		err = tx.QueryRow(ctx, `INSERT INTO reputation_entries(id, tenant_id, source_id, ip_or_cidr, score, action, reason, ttl_seconds, expires_at, status, metadata)
VALUES ($1, NULLIF(current_setting('anti_ddos.tenant_id', true), '')::uuid, $2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (source_id, ip_or_cidr, action, score, ttl_seconds) DO UPDATE SET
    reason=EXCLUDED.reason,
    expires_at=EXCLUDED.expires_at,
    status=EXCLUDED.status,
    metadata=EXCLUDED.metadata,
    last_seen_at=now()
RETURNING id::text`,
			entryID, source.ID, entry.CIDR.String(), entry.Score, entry.Action, entry.Reason, entry.TTLSeconds, expires, status, defaultJSON(entry.Metadata),
		).Scan(&reputationID)
		if err != nil {
			return 0, err
		}
		for _, match := range matches {
			conflictID, err := newUUID()
			if err != nil {
				return 0, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO feed_conflicts(id, tenant_id, source_id, reputation_id, whitelist_id, status)
VALUES ($1, NULLIF(current_setting('anti_ddos.tenant_id', true), '')::uuid, $2,$3,$4,'active')
ON CONFLICT (reputation_id, whitelist_id) DO UPDATE SET status='active', resolved_at=NULL, detected_at=now()`,
				conflictID, source.ID, reputationID, match.WhitelistID,
			); err != nil {
				return 0, err
			}
		}
	}
	nextRun := time.Now().UTC().Add(time.Duration(effectiveFeedIntervalSeconds(source)) * time.Second)
	if _, err := tx.Exec(ctx, `UPDATE feed_sources SET status=$2, active_entries=$3, conflict_count=$4, next_run_at=$5, updated_at=now()
WHERE id=$1`, source.ID, feedStatusHealthy, activeEntries, conflicts, nextRun); err != nil {
		return 0, err
	}
	meta, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, mutationReason("", reason))
	if err != nil {
		return 0, err
	}
	version := uint32(0)
	if meta != nil {
		version = meta.Version
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return version, nil
}

func (s *Store) startFeedRun(ctx context.Context, sourceID string) (FeedRun, error) {
	id, err := newUUID()
	if err != nil {
		return FeedRun{}, err
	}
	var run FeedRun
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return FeedRun{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `INSERT INTO feed_runs(id, tenant_id, source_id, status)
VALUES ($1, NULLIF(current_setting('anti_ddos.tenant_id', true), '')::uuid, $2,'running')
RETURNING id::text, source_id::text, started_at, finished_at, status, items_fetched, items_valid, parse_errors, error, snapshot_version`,
		id, sourceID,
	).Scan(&run.ID, &run.SourceID, &run.StartedAt, &run.FinishedAt, &run.Status, &run.ItemsFetched, &run.ItemsValid, &run.ParseErrors, &run.Error, &run.SnapshotVersion)
	if err != nil {
		return FeedRun{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FeedRun{}, err
	}
	return run, nil
}

func (s *Store) finishFeedRun(ctx context.Context, source FeedSource, runID string, snapshotVersion *uint32, fetched, valid, parseErrors uint32, runErr error) (FeedRun, error) {
	status := "success"
	errText := ""
	version := uint32(0)
	if snapshotVersion != nil {
		version = *snapshotVersion
	}
	if runErr != nil {
		status = "error"
		errText = agentRedactedError(runErr)
	}
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return FeedRun{}, err
	}
	defer tx.Rollback(ctx)
	nextRun := time.Now().UTC().Add(time.Duration(effectiveFeedIntervalSeconds(source)) * time.Second)
	var run FeedRun
	err = tx.QueryRow(ctx, `UPDATE feed_runs
SET finished_at=now(), status=$2, items_fetched=$3, items_valid=$4, parse_errors=$5, error=$6, snapshot_version=$7
WHERE id=$1
RETURNING id::text, source_id::text, started_at, finished_at, status, items_fetched, items_valid, parse_errors, error, snapshot_version`,
		runID, status, fetched, valid, parseErrors, errText, version,
	).Scan(&run.ID, &run.SourceID, &run.StartedAt, &run.FinishedAt, &run.Status, &run.ItemsFetched, &run.ItemsValid, &run.ParseErrors, &run.Error, &run.SnapshotVersion)
	if err != nil {
		return FeedRun{}, err
	}
	if runErr != nil {
		_, err = tx.Exec(ctx, `UPDATE feed_sources
SET status=$2, last_error_at=now(), last_error=$3, parse_error_count=$4, next_run_at=$5, updated_at=now()
WHERE id=$1`, source.ID, feedStatusError, errText, parseErrors, nextRun)
	} else {
		_, err = tx.Exec(ctx, `UPDATE feed_sources
SET status=$2, last_success_at=now(), last_error='', parse_error_count=$3, next_run_at=$4, updated_at=now()
WHERE id=$1`, source.ID, feedStatusHealthy, parseErrors, nextRun)
	}
	if err != nil {
		return FeedRun{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FeedRun{}, err
	}
	if runErr != nil {
		if s.metrics != nil {
			s.metrics.feedSyncErrors.WithLabelValues(boundedMetricValue(source.Name), "sync").Inc()
		}
		_, alertErr := s.CreateSystemAlert(ctx, AlertInput{
			Severity:          "warning",
			Type:              "feed_failure",
			DedupeKey:         "feed_failure:" + source.ID,
			AffectedService:   source.Name,
			Vector:            "threat_feed_sync",
			Evidence:          mustJSON(map[string]any{"source_id": source.ID, "source": source.Name, "error": errText}),
			RecommendedAction: "check feed source connectivity and credentials; last valid entries remain active",
		})
		if alertErr != nil {
			s.logger.Warn("feed failure alert creation failed", "source_id", source.ID, "error", agentRedactedError(alertErr))
		}
		return run, runErr
	}
	if s.metrics != nil {
		s.metrics.feedSyncSuccess.WithLabelValues(boundedMetricValue(source.Name)).Inc()
	}
	return run, nil
}

func (s *Store) GetFeedSource(ctx context.Context, id string) (FeedSource, error) {
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return FeedSource{}, err
	}
	defer tx.Rollback(ctx)
	var source FeedSource
	err = scanFeedSource(tx.QueryRow(ctx, feedSourceSelectSQL()+` WHERE id=$1`, strings.TrimSpace(id)), &source)
	if err != nil {
		return FeedSource{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FeedSource{}, err
	}
	return source, nil
}

func (s *Store) UpdateFeedSource(ctx context.Context, actor *Actor, id string, input FeedSourceInput, reason string) (FeedSource, error) {
	if err := requireOperator(actor); err != nil {
		return FeedSource{}, err
	}
	if actor.Role != RoleAdmin && feedCredentialChangeRequiresAdmin(input.CredentialRef, true) {
		return FeedSource{}, errors.New("admin role required for feed credential changes")
	}
	if err := validateFeedSourceInput(input); err != nil {
		return FeedSource{}, err
	}
	if tenantID := actorTenantID(actor); tenantID != "" {
		ctx = contextWithTenant(ctx, tenantID)
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return FeedSource{}, errors.New("reason is required")
	}
	before, err := s.GetFeedSource(ctx, id)
	if err != nil {
		return FeedSource{}, err
	}
	enabled := before.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	credentialRef := feedCredentialForUpdate(before.CredentialRef, input.CredentialRef)
	interval := input.IntervalSeconds
	if interval == 0 {
		interval = before.IntervalSeconds
	}
	nextRun := time.Now().UTC().Add(time.Duration(effectiveFeedIntervalSeconds(FeedSource{Type: input.Type, IntervalSeconds: interval})) * time.Second)
	tx, err := s.beginActorTenantTx(ctx, actor)
	if err != nil {
		return FeedSource{}, err
	}
	defer tx.Rollback(ctx)
	var source FeedSource
	err = scanFeedSource(tx.QueryRow(ctx, `UPDATE feed_sources SET
    name=$2, type=$3, url=$4, credential_ref=$5, required_for_production=$6, enabled=$7,
    interval_seconds=$8, license_note=$9, quota_metadata=$10, status=$11, next_run_at=$12, updated_at=now()
WHERE id=$1
RETURNING `+feedSourceColumns(),
		id,
		input.Name,
		input.Type,
		input.URL,
		credentialRef,
		input.RequiredForProduction,
		enabled,
		interval,
		input.LicenseNote,
		defaultJSON(input.QuotaMetadata),
		defaultString(input.Status, before.Status),
		nextRun,
	), &source)
	if err != nil {
		return FeedSource{}, err
	}
	if err := insertAudit(ctx, tx, actor, "update_feed_source", "feed_source", source.ID, maskFeedSourceCredential(before), maskFeedSourceCredential(source), reason, ""); err != nil {
		return FeedSource{}, err
	}
	if before.Enabled != source.Enabled {
		if _, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, reason); err != nil {
			return FeedSource{}, err
		}
	}
	return source, tx.Commit(ctx)
}

func (s *Store) ListFeedRuns(ctx context.Context, limit int) ([]FeedRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT r.id::text, r.source_id::text, fs.name, r.started_at, r.finished_at, r.status,
       r.items_fetched, r.items_valid, r.parse_errors, r.error, r.snapshot_version
FROM feed_runs r
JOIN feed_sources fs ON fs.id = r.source_id
ORDER BY r.started_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]FeedRun, 0)
	for rows.Next() {
		var run FeedRun
		if err := rows.Scan(&run.ID, &run.SourceID, &run.SourceName, &run.StartedAt, &run.FinishedAt, &run.Status, &run.ItemsFetched, &run.ItemsValid, &run.ParseErrors, &run.Error, &run.SnapshotVersion); err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) ListFeedConflicts(ctx context.Context) ([]FeedConflict, error) {
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT c.id::text, c.source_id::text, fs.name, c.reputation_id::text, c.whitelist_id::text,
       r.ip_or_cidr::text, w.ip_or_cidr::text, c.status, c.detected_at
FROM feed_conflicts c
JOIN feed_sources fs ON fs.id = c.source_id
JOIN reputation_entries r ON r.id = c.reputation_id
JOIN whitelist_entries w ON w.id = c.whitelist_id
WHERE c.status = 'active'
ORDER BY c.detected_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]FeedConflict, 0)
	for rows.Next() {
		var conflict FeedConflict
		if err := rows.Scan(&conflict.ID, &conflict.SourceID, &conflict.SourceName, &conflict.ReputationID, &conflict.WhitelistID, &conflict.ReputationCIDR, &conflict.WhitelistCIDR, &conflict.Status, &conflict.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, conflict)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) loadFeedWhitelist(ctx context.Context) ([]feedWhitelist, error) {
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, ip_or_cidr::text FROM whitelist_entries
WHERE enabled AND (expires_at IS NULL OR expires_at > now())`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]feedWhitelist, 0)
	for rows.Next() {
		var item feedWhitelist
		var raw string
		if err := rows.Scan(&item.ID, &raw); err != nil {
			return nil, err
		}
		prefix, err := parseCIDR(raw)
		if err != nil {
			return nil, err
		}
		item.Prefix = prefix
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func matchingWhitelists(prefix netip.Prefix, whitelist []feedWhitelist) []conflictMatch {
	out := make([]conflictMatch, 0)
	for _, item := range whitelist {
		if prefixesOverlap(prefix, item.Prefix) {
			out = append(out, conflictMatch{WhitelistID: item.ID})
		}
	}
	return out
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

func prefixContainsAnyWhitelist(prefix netip.Prefix, whitelist []feedWhitelist) bool {
	for _, item := range whitelist {
		if prefix.Contains(item.Prefix.Addr()) {
			return true
		}
	}
	return false
}

func feedMergeCompatible(a, b normalizedFeedEntry) bool {
	return a.Action == b.Action && a.Score == b.Score && a.TTLSeconds == b.TTLSeconds && a.Reason == b.Reason
}

func siblingPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	bits := prefix.Bits()
	if bits <= 0 || bits > 32 || !prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}
	size := uint32(1) << uint32(32-bits)
	addr := addrToUint32(prefix.Addr())
	sibling := addr ^ size
	return netip.PrefixFrom(uint32ToAddr(sibling), bits).Masked(), true
}

func parentPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	bits := prefix.Bits()
	if bits <= 0 || bits > 32 || !prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(prefix.Addr(), bits-1).Masked(), true
}

func addrToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func sortFeedEntries(entries []normalizedFeedEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CIDR.String() != entries[j].CIDR.String() {
			return entries[i].CIDR.String() < entries[j].CIDR.String()
		}
		if entries[i].Score != entries[j].Score {
			return entries[i].Score > entries[j].Score
		}
		return entries[i].TTLSeconds < entries[j].TTLSeconds
	})
}

func normalizeFeedType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "spamhaus_drop", "spamhaus":
		return "spamhaus_drop"
	case "team_cymru", "cymru", "bogon", "fullbogon":
		return "team_cymru"
	case "abuseipdb", "abuseipdb_v2":
		return "abuseipdb"
	case "internal", "internal_http_json", "json":
		return "internal_json"
	default:
		return value
	}
}

func defaultTTLSeconds(source FeedSource, fallback time.Duration) uint32 {
	quota := rawJSONMap(source.QuotaMetadata)
	if ttl := intFromQuota(quota, "ttl_seconds", 0); ttl > 0 {
		return uint32(ttl)
	}
	return uint32(fallback / time.Second)
}

func effectiveFeedIntervalSeconds(source FeedSource) uint32 {
	interval := source.IntervalSeconds
	if interval == 0 {
		interval = 3600
	}
	if normalizeFeedType(source.Type) == "team_cymru" && interval < 4*3600 {
		return 4 * 3600
	}
	return interval
}

func rawJSONMap(raw json.RawMessage) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func intFromQuota(quota map[string]any, key string, fallback int) int {
	value, ok := quota[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func feedCredentialInputValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func feedCredentialChangeRequiresAdmin(value *string, update bool) bool {
	if value == nil {
		return false
	}
	trimmed := feedCredentialInputValue(value)
	if trimmed == feedCredentialMask {
		return false
	}
	if update {
		return true
	}
	return trimmed != ""
}

func feedCredentialForCreate(value *string) string {
	trimmed := feedCredentialInputValue(value)
	if trimmed == feedCredentialMask {
		return ""
	}
	return trimmed
}

func feedCredentialForUpdate(current string, value *string) string {
	if value == nil {
		return current
	}
	trimmed := feedCredentialInputValue(value)
	if trimmed == feedCredentialMask {
		return current
	}
	return trimmed
}

func maskFeedSourceCredential(source FeedSource) FeedSource {
	if strings.TrimSpace(source.CredentialRef) != "" {
		source.CredentialRef = feedCredentialMask
	}
	return source
}

func maskFeedSourceCredentials(sources []FeedSource) []FeedSource {
	out := make([]FeedSource, len(sources))
	for i, source := range sources {
		out[i] = maskFeedSourceCredential(source)
	}
	return out
}

func resolveCredentialRef(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "none"
	}
	if ref == feedCredentialMask {
		return "", "masked"
	}
	var envKey string
	switch {
	case strings.HasPrefix(ref, "env://"):
		envKey = strings.TrimPrefix(ref, "env://")
	case strings.HasPrefix(ref, "secret://anti-ddos/"):
		name := strings.TrimPrefix(ref, "secret://anti-ddos/")
		envKey = "ANTI_DDOS_SECRET_" + envName(name)
	default:
		if strings.Contains(ref, "://") {
			return "", "invalid"
		}
		return ref, "present"
	}
	value := strings.TrimSpace(os.Getenv(envKey))
	if value == "" {
		return "", "missing"
	}
	return value, "present"
}

func envName(value string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(value) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func agentRedactedError(err error) string {
	if err == nil {
		return ""
	}
	return agent.RedactString(err.Error())
}
