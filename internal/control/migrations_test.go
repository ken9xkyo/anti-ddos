package control

import "testing"

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
