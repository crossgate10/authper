package authper

import (
	"errors"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gocraft/dbr/v2"
	"github.com/lib/pq"
	"github.com/mmcloughlin/meow"
)

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	ID    string
	PType string `db:"ptype"`
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

func (r *CasbinRule) String() string {
	const prefixLine = ", "
	var sb strings.Builder

	sb.Grow(
		len(r.PType) +
			len(r.V0) + len(r.V1) + len(r.V2) +
			len(r.V3) + len(r.V4) + len(r.V5),
	)

	sb.WriteString(r.PType)
	if len(r.V0) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V0)
	}
	if len(r.V1) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V1)
	}
	if len(r.V2) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V2)
	}
	if len(r.V3) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V3)
	}
	if len(r.V4) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V4)
	}
	if len(r.V5) > 0 {
		sb.WriteString(prefixLine)
		sb.WriteString(r.V5)
	}

	return sb.String()
}

type Filter struct {
	P []string
	G []string
}

func NewPGAdapter(dbConn *dbr.Connection) (*PGAdapter, error) {
	a := &PGAdapter{
		dbConn: dbConn,
	}
	if err := a.createTableIfNotExists(); err != nil {
		return nil, fmt.Errorf("pgadapter.NewAdapter: %v", err)
	}
	return a, nil
}

type PGAdapter struct {
	dbConn   *dbr.Connection
	filtered bool
}

func (a *PGAdapter) createTableIfNotExists() error {
	sess := a.dbConn.NewSession(nil)

	_, err := sess.Exec(createSchema)
	if e, ok := err.(*pq.Error); ok && e.Code == errDuplicateTable {
		// fallthrough
	} else if err != nil {
		return err
	}
	return nil
}

func (a *PGAdapter) LoadPolicy(model model.Model) error {
	sess := a.dbConn.NewSession(nil)

	var lines []*CasbinRule
	if _, err := sess.Select(tableCasbinRuleColumns...).
		From(tableCasbinRule).
		Load(&lines); err != nil {
		return err
	}

	for _, line := range lines {
		persist.LoadPolicyLine(line.String(), model)
	}

	a.filtered = false

	return nil
}

func policyID(ptype string, rule []string) string {
	data := strings.Join(append([]string{ptype}, rule...), ",")
	sum := meow.Checksum(0, []byte(data))
	return fmt.Sprintf("%x", sum)
}

func savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{PType: ptype}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	line.ID = policyID(ptype, rule)

	return line
}

func (a *PGAdapter) SavePolicy(model model.Model) error {
	sess := a.dbConn.NewSession(nil)

	tx, err := sess.Begin()
	if err != nil {
		return err
	}
	defer tx.RollbackUnlessCommitted()

	if _, err = tx.DeleteFrom(tableCasbinRule).Exec(); err != nil {
		return err
	}

	var lines []*CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	if len(lines) > 0 {
		builder := tx.InsertInto(tableCasbinRule).
			Columns(tableCasbinRuleColumns...)
		for _, line := range lines {
			builder.Values(line)
		}
		_, err = builder.Exec()
		if err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit DB transaction: %v", err)
	}

	return nil
}

func (a *PGAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	sess := a.dbConn.NewSession(nil)

	tx, err := sess.Begin()
	if err != nil {
		return err
	}
	defer tx.RollbackUnlessCommitted()

	l := &dataLoader{Runner: tx}
	_, err = l.InsertWithSuffix(tx.InsertInto(tableCasbinRule).
		Columns(tableCasbinRuleColumns...).
		Record(line),
		onConflictDoNothing)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *PGAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []*CasbinRule
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}

	sess := a.dbConn.NewSession(nil)

	tx, err := sess.Begin()
	if err != nil {
		return err
	}
	defer tx.RollbackUnlessCommitted()

	l := &dataLoader{Runner: tx}
	builder := tx.InsertInto(tableCasbinRule).
		Columns(tableCasbinRuleColumns...)
	for _, line := range lines {
		builder.Values(line)
	}
	if _, err = l.InsertWithSuffix(builder, onConflictDoNothing); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *PGAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	sess := a.dbConn.NewSession(nil)

	tx, err := sess.Begin()
	if err != nil {
		return err
	}
	defer tx.RollbackUnlessCommitted()

	_, err = tx.DeleteFrom(tableCasbinRule).
		Where(dbr.Eq(colID, line.ID)).
		Exec()
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *PGAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	l := len(rules)
	ids := make([]string, l)
	lines := make([]*CasbinRule, l)
	for i, rule := range rules {
		line := savePolicyLine(ptype, rule)
		lines[i] = line
		ids[i] = line.ID
	}

	sess := a.dbConn.NewSession(nil)

	tx, err := sess.Begin()
	if err != nil {
		return err
	}
	defer tx.RollbackUnlessCommitted()

	_, err = tx.DeleteFrom(tableCasbinRule).
		Where(dbr.Eq(colID, ids)).
		Exec()
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *PGAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}
