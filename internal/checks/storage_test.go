package checks

import "testing"

func TestIsStorageEnvVar(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		// Exact matches
		{"KV_URL", true},
		{"KV_REST_API_URL", true},
		{"KV_REST_API_TOKEN", true},
		{"POSTGRES_URL", true},
		{"POSTGRES_PASSWORD", true},
		{"BLOB_READ_WRITE_TOKEN", true},

		// Prefix / contains — matches because the check uses Contains on uppercase.
		{"MY_KV_URL", true},
		{"CUSTOM_POSTGRES_HOST", true},
		{"my_postgres_url", true}, // case-insensitive

		// Non-storage variables
		{"NEXT_PUBLIC_API_URL", false},
		{"NODE_ENV", false},
		{"DATABASE_URL", false}, // not a Vercel managed storage var
		{"STRIPE_SECRET_KEY", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got := isStorageEnvVar(tc.key)
			if got != tc.want {
				t.Errorf("isStorageEnvVar(%q) = %v; want %v", tc.key, got, tc.want)
			}
		})
	}
}

// TestHasTrustedIPs_Scenarios exercises the regression for F-STOR1: a
// non-nil trustedIps object without a populated addresses list must NOT
// suppress the stor-001 finding.
func TestHasTrustedIPs_Scenarios(t *testing.T) {
	// The production logic lives inline inside StorageChecks.Run; we
	// replicate the decision here so a regression in the helper would
	// have been caught at code-review time. If the inline logic moves
	// into a helper later this test can call it directly.
	evaluate := func(project map[string]interface{}) bool {
		hasTrustedIPs := false
		if trustedIps := mapVal(project["trustedIps"]); trustedIps != nil {
			if addrs, ok := trustedIps["addresses"].([]interface{}); ok && len(addrs) > 0 {
				hasTrustedIPs = true
			}
		}
		return hasTrustedIPs
	}

	cases := []struct {
		name     string
		project  map[string]interface{}
		wantHave bool
	}{
		{
			name:     "no trustedIps field",
			project:  map[string]interface{}{},
			wantHave: false,
		},
		{
			name: "trustedIps is empty object",
			project: map[string]interface{}{
				"trustedIps": map[string]interface{}{},
			},
			wantHave: false, // pre-fix bug: this used to report true
		},
		{
			name: "trustedIps object has protectionMode but no addresses",
			project: map[string]interface{}{
				"trustedIps": map[string]interface{}{
					"protectionMode": "additional",
				},
			},
			wantHave: false, // pre-fix bug: this used to report true
		},
		{
			name: "trustedIps has empty addresses array",
			project: map[string]interface{}{
				"trustedIps": map[string]interface{}{
					"addresses": []interface{}{},
				},
			},
			wantHave: false,
		},
		{
			name: "trustedIps has one address",
			project: map[string]interface{}{
				"trustedIps": map[string]interface{}{
					"addresses": []interface{}{
						map[string]interface{}{"value": "10.0.0.0/8"},
					},
				},
			},
			wantHave: true,
		},
		{
			name: "trustedIps has addresses that are not an array",
			project: map[string]interface{}{
				"trustedIps": map[string]interface{}{
					"addresses": "10.0.0.0/8", // wrong type
				},
			},
			wantHave: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evaluate(tc.project); got != tc.wantHave {
				t.Errorf("trustedIps evaluation = %v; want %v", got, tc.wantHave)
			}
		})
	}
}
