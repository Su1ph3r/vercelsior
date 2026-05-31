package checks

import "testing"

func TestIsFullAccessScopes(t *testing.T) {
	cases := []struct {
		name   string
		scopes interface{}
		want   bool
	}{
		{"nil (absent)", nil, true},
		{"empty array", []interface{}{}, true},
		{"empty object", map[string]interface{}{}, true},
		{"non-empty array (scoped)", []interface{}{"read:project"}, false},
		{"non-empty object (scoped)", map[string]interface{}{"read": true}, false},
		// Unrecognized shapes must NOT report full-access (avoid false-positive
		// HIGH on a payload we don't model).
		{"string shape", "all", false},
		{"number shape", float64(1), false},
		{"bool shape", true, false},
	}
	for _, tc := range cases {
		if got := isFullAccessScopes(tc.scopes); got != tc.want {
			t.Errorf("%s: isFullAccessScopes(%v) = %v; want %v", tc.name, tc.scopes, got, tc.want)
		}
	}
}
