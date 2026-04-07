package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catTLS = "Certificates & TLS"

type TLSChecks struct{}

func (t *TLSChecks) Name() string     { return "TLS" }
func (t *TLSChecks) Category() string { return catTLS }

func (t *TLSChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	certs, err := c.ListCertificates()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"tls-001", "Certificate Enumeration — Insufficient Permissions", catTLS,
				"Cannot list certificates: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "tls-001", Title: "Certificate Enumeration", Category: catTLS,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list certificates: %v", err),
				ResourceType: "certificate", ResourceID: "N/A",
			})
		}
		return findings
	}

	now := time.Now()
	fourteenDays := 14 * 24 * time.Hour
	thirtyDays := 30 * 24 * time.Hour

	for _, cert := range certs {
		certID := str(cert["id"])
		certName := str(cert["cns"])
		if certName == "" {
			if cns, ok := cert["cns"].([]interface{}); ok && len(cns) > 0 {
				certName = str(cns[0])
			}
		}
		if certName == "" {
			certName = str(cert["domain"])
		}
		displayName := certName
		if displayName == "" {
			displayName = certID
		}

		// Try multiple field names for expiration
		var expiresAt time.Time
		var parsed bool
		for _, field := range []string{"expiration", "expiresAt", "expires_at"} {
			val := cert[field]
			if val == nil {
				continue
			}
			switch v := val.(type) {
			case string:
				for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02"} {
					if t, err := time.Parse(layout, v); err == nil {
						expiresAt = t
						parsed = true
						break
					}
				}
			case float64:
				// Unix timestamp in seconds or milliseconds
				if v > 1e12 {
					expiresAt = time.UnixMilli(int64(v))
				} else {
					expiresAt = time.Unix(int64(v), 0)
				}
				parsed = true
			}
			if parsed {
				break
			}
		}

		if !parsed {
			continue
		}

		remaining := expiresAt.Sub(now)

		switch {
		case remaining <= 0:
			// Already expired
			findings = append(findings, fail(
				"tls-001", "Certificate Expired", catTLS,
				models.Critical, 9.0,
				"An expired TLS certificate causes browser security warnings or silent failures. Let's Encrypt auto-renewal can fail without notice.",
				fmt.Sprintf("Certificate for '%s' expired on %s.", displayName, expiresAt.Format("2006-01-02")),
				"certificate", certID, displayName,
				"Renew the certificate or investigate why auto-renewal failed.",
				map[string]string{"expires_at": expiresAt.Format(time.RFC3339)},
			))
		case remaining <= fourteenDays:
			// Expiring within 14 days
			findings = append(findings, fail(
				"tls-001", "Certificate Expiring Soon", catTLS,
				models.High, 8.0,
				"An expired TLS certificate causes browser security warnings or silent failures. Let's Encrypt auto-renewal can fail without notice.",
				fmt.Sprintf("Certificate for '%s' expires in %d days (%s).", displayName, int(remaining.Hours()/24), expiresAt.Format("2006-01-02")),
				"certificate", certID, displayName,
				"Renew the certificate or investigate why auto-renewal failed.",
				map[string]string{"expires_at": expiresAt.Format(time.RFC3339), "days_remaining": fmt.Sprintf("%d", int(remaining.Hours()/24))},
			))
		case remaining <= thirtyDays:
			// Expiring within 30 days
			findings = append(findings, warn(
				"tls-001", "Certificate Expiring Soon", catTLS,
				models.Medium, 6.0,
				"An expired TLS certificate causes browser security warnings or silent failures. Let's Encrypt auto-renewal can fail without notice.",
				fmt.Sprintf("Certificate for '%s' expires in %d days (%s).", displayName, int(remaining.Hours()/24), expiresAt.Format("2006-01-02")),
				"certificate", certID, displayName,
				"Renew the certificate or investigate why auto-renewal failed.",
				map[string]string{"expires_at": expiresAt.Format(time.RFC3339), "days_remaining": fmt.Sprintf("%d", int(remaining.Hours()/24))},
			))
		default:
			findings = append(findings, pass(
				"tls-001", "Certificate Valid", catTLS,
				fmt.Sprintf("Certificate for '%s' is valid until %s.", displayName, expiresAt.Format("2006-01-02")),
				"certificate", certID, displayName,
			))
		}

		// Check: weak key algorithm
		keyAlg := str(cert["keyAlgorithm"])
		if keyAlg == "" {
			keyAlg = str(cert["algorithm"])
		}
		if keyAlg != "" {
			weakAlgs := map[string]bool{"rsa-1024": true, "rsa-2048": false, "sha1": true, "md5": true}
			if isWeak, known := weakAlgs[strings.ToLower(keyAlg)]; known && isWeak {
				findings = append(findings, fail(
					"tls-003", "Certificate Using Weak Key Algorithm", catTLS, models.High,
					7.0, "Weak key algorithms are vulnerable to brute-force attacks. RSA-1024, SHA1, and MD5 are considered broken.",
					fmt.Sprintf("Certificate '%s' uses weak key algorithm: %s", certName, keyAlg),
					"certificate", certID, certName,
					"Reissue the certificate with a modern algorithm (RSA-2048+ or ECDSA P-256+).",
					map[string]string{"algorithm": keyAlg},
				))
			}
		}

		// Check: certificate key size too small (if available as numeric field)
		if keySize := num(cert["keySize"]); keySize > 0 && keySize < 2048 {
			findings = append(findings, fail(
				"tls-003", "Certificate Key Size Too Small", catTLS, models.High,
				7.0, "Key sizes below 2048 bits are considered insecure and vulnerable to factoring attacks.",
				fmt.Sprintf("Certificate '%s' has a key size of %.0f bits.", certName, keySize),
				"certificate", certID, certName,
				"Reissue the certificate with at least 2048-bit RSA or 256-bit ECDSA key.",
				map[string]string{"key_size": fmt.Sprintf("%.0f", keySize)},
			))
		}
	}

	// Check: mTLS for backend connections (Enterprise/Secure Compute feature)
	projects, projErr := c.ListProjects()
	if projErr != nil {
		if IsPermissionDenied(projErr) {
			findings = append(findings, permissionFinding(
				"tls-010", "mTLS Check — Insufficient Permissions", catTLS,
				"Cannot list projects for mTLS check: API token lacks required permissions. This check was skipped.",
			))
		}
	} else {
		permSeenTLS := make(map[string]bool)
		for _, p := range projects {
			projID := str(p["id"])
			projName := str(p["name"])

			// Check if project has secure compute or backend connections that would benefit from mTLS
			// Look for mTLS config indicators in project settings
			security := mapVal(p["security"])
			hasMTLS := false
			if security != nil {
				if mtls := mapVal(security["mtls"]); mtls != nil {
					hasMTLS = boolean(mtls["enabled"])
				}
			}

			// Only flag if the project seems to connect to backends (has DB/API env vars)
			// but doesn't have mTLS configured
			if !hasMTLS {
				envVars, envErr := c.ListProjectEnvVars(projID)
				if envErr != nil {
					if IsPermissionDenied(envErr) && !permSeenTLS["ListProjectEnvVars"] {
						permSeenTLS["ListProjectEnvVars"] = true
						findings = append(findings, permissionFinding(
							"tls-010", "mTLS Env Var Check — Insufficient Permissions", catTLS,
							"Cannot list project environment variables: API token lacks required permissions. This check was skipped for all projects.",
						))
					}
					continue
				}
				hasBackend := false
				for _, env := range envVars {
					key := strings.ToUpper(str(env["key"]))
					if strings.Contains(key, "DATABASE_URL") || strings.Contains(key, "DB_HOST") ||
						strings.Contains(key, "BACKEND_URL") || strings.Contains(key, "API_ENDPOINT") {
						hasBackend = true
						break
					}
				}
				if hasBackend {
					findings = append(findings, warn(
						"tls-002", "No mTLS for Backend Connections", catTLS, models.Low,
						4.0, "Without mTLS, backend services cannot verify that requests originate from your Vercel deployment. Attackers who discover backend URLs can connect directly.",
						fmt.Sprintf("Project '%s' connects to backend services but does not have mutual TLS configured.", projName),
						"project", projID, projName,
						"Configure mTLS client certificates for projects that connect to sensitive backend services.",
						nil,
					))
				}
			}
		}
	}

	return findings
}
