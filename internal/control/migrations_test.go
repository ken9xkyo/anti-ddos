package control

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigrationsHaveUniqueIncreasingVersions(t *testing.T) {
	seen := make(map[int]string, len(Migrations))
	previous := 0
	for _, migration := range Migrations {
		if migration.Version <= previous {
			t.Fatalf("migration %s version %d is not greater than previous version %d", migration.Name, migration.Version, previous)
		}
		if migration.Name == "" {
			t.Fatalf("migration version %d has empty name", migration.Version)
		}
		if previousName, ok := seen[migration.Version]; ok {
			t.Fatalf("migration version %d is duplicated by %s and %s", migration.Version, previousName, migration.Name)
		}
		seen[migration.Version] = migration.Name
		previous = migration.Version
	}
}

func TestOperatorSingleTenantMigrationFailsOnExistingViolation(t *testing.T) {
	dsn := os.Getenv("ANTI_DDOS_CONTROL_TEST_DSN")
	if dsn == "" {
		t.Skip("ANTI_DDOS_CONTROL_TEST_DSN is not set")
	}
	ctx := context.Background()
	pool, err := OpenPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := runMigrationsThrough(ctx, pool, 7); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO tenants(id, slug, name, status)
VALUES ('00000000-0000-4000-8000-000000001101', 'tenant-b', 'Tenant B', 'active');
INSERT INTO app_users(id, username, password_hash, role, platform_role, status)
VALUES ('00000000-0000-4000-8000-000000002101', 'multi-operator', 'unused', 'operator', '', 'active');
INSERT INTO tenant_memberships(id, tenant_id, user_id, role, status)
VALUES
  ('00000000-0000-4000-8000-000000003101', '00000000-0000-4000-8000-000000001000', '00000000-0000-4000-8000-000000002101', 'operator', 'active'),
  ('00000000-0000-4000-8000-000000003102', '00000000-0000-4000-8000-000000001101', '00000000-0000-4000-8000-000000002101', 'viewer', 'active');
`)
	if err != nil {
		t.Fatal(err)
	}
	err = RunMigrations(ctx, pool)
	if err == nil || !strings.Contains(err.Error(), "operator_single_tenant migration blocked") {
		t.Fatalf("RunMigrations error=%v, want operator_single_tenant preflight failure", err)
	}
}

func runMigrationsThrough(ctx context.Context, pool *pgxpool.Pool, maxVersion int) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return err
	}
	for _, migration := range Migrations {
		if migration.Version > maxVersion {
			break
		}
		if _, err := tx.Exec(ctx, migration.SQL); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version, name) VALUES ($1, $2)`, migration.Version, migration.Name); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
