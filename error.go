package authper

import "github.com/lib/pq"

var (
	errDuplicateTable = pq.ErrorCode("42P07")
	errDuplicateKey   = pq.ErrorCode("42701")
)
