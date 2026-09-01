package db

import (
	"database/sql"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sql.DB

// Init initializes the database connection using the provided connection string.
func Init(connString string) error {
	var err error
	DB, err = sql.Open("pgx", connString)
	if err != nil {
		return err
	}

	if err = DB.Ping(); err != nil {
		return err
	}

	schema, err := os.ReadFile("db/schema.sql")
	if err != nil {
		return err
	}

	_, err = DB.Exec(string(schema))
	return err
}
