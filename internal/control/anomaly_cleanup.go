package control

import (
	"context"
	"errors"
)

const legacyAutoEnforceDisableReason = "baseline anomaly detection is alert-only"

func (s *Store) DisableLegacyAutoEnforceRules(ctx context.Context) (int, error) {
	if tenantIDFromContext(ctx) == "" {
		tenantIDs, err := s.activeTenantIDs(ctx)
		if err != nil {
			return 0, err
		}
		total := 0
		var joined error
		for _, tenantID := range tenantIDs {
			count, err := s.DisableLegacyAutoEnforceRules(contextWithTenant(ctx, tenantID))
			total += count
			if err != nil {
				joined = errors.Join(joined, err)
			}
		}
		return total, joined
	}
	tx, err := s.beginContextTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, COALESCE(service_id::text, ''), name, priority, match_expr, action, mode,
       threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
       ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, created_at, updated_at
FROM rules
WHERE enabled AND (owner=$1 OR evidence->>'auto_enforce' = 'true')
ORDER BY created_at
FOR UPDATE`, legacyAutoEnforceOwner)
	if err != nil {
		return 0, err
	}
	var legacyRules []Rule
	for rows.Next() {
		var rule Rule
		if err := scanRule(rows, &rule); err != nil {
			rows.Close()
			return 0, err
		}
		legacyRules = append(legacyRules, rule)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	if len(legacyRules) == 0 {
		return 0, tx.Commit(ctx)
	}

	disabled := 0
	for _, before := range legacyRules {
		var after Rule
		err := scanRule(tx.QueryRow(ctx, `UPDATE rules SET enabled=false, updated_at=now()
WHERE id=$1
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), name, priority, match_expr, action, mode,
          threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
          ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, created_at, updated_at`, before.ID), &after)
		if err != nil {
			return 0, err
		}
		if err := insertAudit(ctx, tx, nil, "disable_legacy_auto_enforce_rule", "rule", before.ID, before, after, legacyAutoEnforceDisableReason, ""); err != nil {
			return 0, err
		}
		disabled++
	}
	if _, err := s.rebuildSnapshotInTx(ctx, tx, nil, nil, legacyAutoEnforceDisableReason); err != nil {
		return 0, err
	}
	return disabled, tx.Commit(ctx)
}
