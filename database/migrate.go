// The package database handles the methods and definition to manipulate a database.
package database

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrations embed.FS

// InitialMigration migrate a sqlite3 database if necessary.
func InitialMigration(db *sql.DB) error {
	dbDriver, err := sqlite.WithInstance(db, &sqlite.Config{
		NoTxWrap: true,
	})
	if err != nil {
		slog.Error("db failed", slog.String("err", err.Error()))
		return err
	}
	iofsDriver, err := iofs.New(migrations, "migrations")
	if err != nil {
		slog.Error("db failed", slog.String("err", err.Error()))
		return err
	}
	defer iofsDriver.Close()
	m, err := migrate.NewWithInstance(
		"iofs",
		iofsDriver,
		"sqlite",
		dbDriver,
	)
	if err != nil {
		slog.Error("db failed", slog.String("err", err.Error()))
		return err
	}
	if version, dirty, err := m.Version(); err == migrate.ErrNilVersion {
		slog.Warn("no migrations detected", slog.String("err", err.Error()))
		if err = m.Up(); err != nil {
			panic(fmt.Errorf("failed to migrate db: %w", err))
		}
		slog.Info("db migrated")
	} else if dirty {
		panic("db is in dirty state.")
	} else if err != nil {
		panic(fmt.Errorf("failed to fetch DB version: %w", err))
	} else {
		slog.Info("db version detected", slog.Uint64("version", uint64(version)))
		if newVersion, err := iofsDriver.Next(version); err != nil {
			slog.Info("latest DB version", slog.Uint64("version", uint64(version)))
		} else {
			slog.Info("new DB version detected", slog.Uint64("actual", uint64(version)), slog.Uint64("new", uint64(newVersion)))
			if err = m.Up(); err != nil {
				panic(fmt.Errorf("failed to migrate db: %w", err))
			}
			slog.Info("db migrated")
		}
	}
	return nil
}
