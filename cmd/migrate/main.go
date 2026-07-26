package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/qf-studio/auth-service/migrations"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: migrate <up|down|version|force <N>>")
		os.Exit(1)
	}

	dsn, err := databaseURL()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	m, err := newMigrate(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := run(m, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// databaseURL returns a postgres:// connection URL from DATABASE_URL or from
// individual POSTGRES_* environment variables matching internal/config.PostgresConfig.
func databaseURL() (string, error) {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v, nil
	}

	host := os.Getenv("POSTGRES_HOST")
	dbName := os.Getenv("POSTGRES_DB")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")

	if host == "" || dbName == "" || user == "" || password == "" {
		return "", fmt.Errorf("set DATABASE_URL or POSTGRES_HOST, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD")
	}

	port := os.Getenv("POSTGRES_PORT")
	if port == "" {
		port = "5432"
	}
	sslMode := os.Getenv("POSTGRES_SSLMODE")
	if sslMode == "" {
		sslMode = "disable"
	}

	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   host + ":" + port,
		Path:   dbName,
		RawQuery: url.Values{
			"sslmode": {sslMode},
		}.Encode(),
	}
	return u.String(), nil
}

// newMigrate creates a *migrate.Migrate instance using the embedded migration
// source and the given postgres DSN.
func newMigrate(dsn string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("opening embedded migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return nil, fmt.Errorf("creating migrate instance: %w", err)
	}
	return m, nil
}

// run executes the given subcommand (and any trailing arguments) against the
// migrate instance.
func run(m *migrate.Migrate, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command given (use up, down, version, or force)")
	}

	cmd := args[0]
	switch cmd {
	case "up":
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("migrate up: %w", err)
		}
		fmt.Println("migrations applied successfully")
		return nil

	case "down":
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("migrate down: %w", err)
		}
		fmt.Println("migrations reverted successfully")
		return nil

	case "version":
		version, dirty, err := m.Version()
		if err != nil {
			return fmt.Errorf("migrate version: %w", err)
		}
		dirtyStr := ""
		if dirty {
			dirtyStr = " (dirty)"
		}
		fmt.Println(strconv.FormatUint(uint64(version), 10) + dirtyStr)
		return nil

	case "force":
		// Decision: force takes an explicit target version so operators can
		// recover from a dirty schema_migrations row (e.g. after a failed
		// migration) without hand-editing the database, per the 2026-07-24
		// Pointer incident.
		if len(args) < 2 {
			return fmt.Errorf("force requires a version argument, e.g. force 3")
		}
		version, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid version %q for force: %w", args[1], err)
		}
		if err := m.Force(version); err != nil {
			return fmt.Errorf("migrate force: %w", err)
		}
		fmt.Printf("forced schema_migrations version to %d\n", version)
		return nil

	default:
		return fmt.Errorf("unknown command %q (use up, down, version, or force)", cmd)
	}
}
