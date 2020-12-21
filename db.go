package authper

const (
	createSchema = `CREATE TABLE public.casbin_rules (
	id varchar NOT NULL DEFAULT '',
	ptype varchar NOT NULL DEFAULT '',
	v0 varchar NOT NULL DEFAULT '',
	v1 varchar NOT NULL DEFAULT '',
	v2 varchar NOT NULL DEFAULT '',
	v3 varchar NOT NULL DEFAULT '',
	v4 varchar NOT NULL DEFAULT '',
	v5 varchar NOT NULL DEFAULT '',
	CONSTRAINT casbin_rules_pk PRIMARY KEY (id),
	CONSTRAINT casbin_rules_un UNIQUE (v0, v1, v2, v3, v4, v5));`
)

var (
	tableCasbinRule        = "casbin_rules"
	tableCasbinRuleColumns = []string{
		"id",
		"ptype",
		"v0",
		"v1",
		"v2",
		"v3",
		"v4",
		"v5",
	}
)

var (
	colID    = "id"
	colPType = "ptype"
	colV0    = "v0"
	colV1    = "v1"
	colV2    = "v2"
	colV3    = "v3"
	colV4    = "v4"
	colV5    = "v5"
)
