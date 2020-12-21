package authper

import (
	"database/sql"
	"fmt"

	"github.com/gocraft/dbr/v2"
)

const (
	onConflictDoNothing = "on conflict do nothing"
	onConflict          = "on conflict"
	doNothing           = "do nothing"
)

type dataLoader struct {
	Runner dbr.SessionRunner
}

func interpolate(builder dbr.Builder, d dbr.Dialect) (string, error) {
	buff := dbr.NewBuffer()
	err := builder.Build(d, buff)
	if err != nil {
		return "", err
	}
	raw, err := dbr.InterpolateForDialect(buff.String(), buff.Value(), d)
	if err != nil {
		return "", err
	}
	return raw, nil
}

func (l *dataLoader) InsertWithSuffix(stmt *dbr.InsertStmt, suffix string) (sql.Result, error) {
	raw, err := interpolate(stmt, stmt.Dialect)
	if err != nil {
		return nil, err
	}
	tx, ok := l.Runner.(*dbr.Tx)
	if ok {
		return tx.Exec(fmt.Sprintf("%s %s", raw, suffix))
	}
	sess, ok := l.Runner.(*dbr.Session)
	if ok {
		return sess.Exec(fmt.Sprintf("%s %s", raw, suffix))
	}
	return nil, fmt.Errorf("unknown dbr runner %v", l.Runner)
}
