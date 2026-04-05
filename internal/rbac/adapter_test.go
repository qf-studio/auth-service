package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPad6(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, []string{"", "", "", "", "", ""}},
		{"one", []string{"a"}, []string{"a", "", "", "", "", ""}},
		{"three", []string{"a", "b", "c"}, []string{"a", "b", "c", "", "", ""}},
		{"six", []string{"a", "b", "c", "d", "e", "f"}, []string{"a", "b", "c", "d", "e", "f"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pad6(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTrimEmpty(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"all empty", []string{"", "", ""}, nil},
		{"trailing empty", []string{"a", "b", "", ""}, []string{"a", "b"}},
		{"no empty", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"middle empty kept", []string{"a", "", "c"}, []string{"a", "", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimEmpty(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuleToWhere(t *testing.T) {
	where, args := ruleToWhere("p", []string{"admin", "users", "read"})
	assert.Equal(t, "ptype = $1 AND v0 = $2 AND v1 = $3 AND v2 = $4 AND v3 = $5 AND v4 = $6 AND v5 = $7", where)
	assert.Equal(t, []any{"p", "admin", "users", "read", "", "", ""}, args)
}

func TestPolicyFilter_ToWhereClause(t *testing.T) {
	tests := []struct {
		name      string
		filter    PolicyFilter
		wantSQL   string
		wantArgs  []any
	}{
		{
			name:     "empty filter",
			filter:   PolicyFilter{},
			wantSQL:  "",
			wantArgs: nil,
		},
		{
			name:     "ptype only",
			filter:   PolicyFilter{PType: "p"},
			wantSQL:  " WHERE ptype = $1",
			wantArgs: []any{"p"},
		},
		{
			name:     "ptype and v0",
			filter:   PolicyFilter{PType: "p", V0: "admin"},
			wantSQL:  " WHERE ptype = $1 AND v0 = $2",
			wantArgs: []any{"p", "admin"},
		},
		{
			name:     "all fields",
			filter:   PolicyFilter{PType: "g", V0: "alice", V1: "admin", V2: ""},
			wantSQL:  " WHERE ptype = $1 AND v0 = $2 AND v1 = $3",
			wantArgs: []any{"g", "alice", "admin"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sql, args := tt.filter.toWhereClause()
			assert.Equal(t, tt.wantSQL, sql)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}

func TestNewModel(t *testing.T) {
	m, err := newModel()
	assert.NoError(t, err)
	assert.NotNil(t, m)
	// Verify the model has the expected sections.
	assert.Contains(t, m, "r")
	assert.Contains(t, m, "p")
	assert.Contains(t, m, "g")
	assert.Contains(t, m, "e")
	assert.Contains(t, m, "m")
}
