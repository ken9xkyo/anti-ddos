package agent

import (
	"regexp"
	"sort"
	"strings"
)

const redactedValue = "[REDACTED]"

var (
	sensitiveKeyParts = []string{
		"token",
		"secret",
		"password",
		"passwd",
		"dsn",
		"api_key",
		"apikey",
		"authorization",
		"cookie",
		"session",
	}
	telegramTokenRE = regexp.MustCompile(`\b\d{6,}:[A-Za-z0-9_-]{20,}\b`)
	dsnRE           = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:)[^@\s]+(@)`)
	querySecretRE   = regexp.MustCompile(`(?i)([?&](?:token|key|api_key|apikey|password|secret)=)[^&\s]+`)
	authHeaderRE    = regexp.MustCompile(`(?i)(authorization:\s*)[^\r\n]+`)
)

func RedactKeyValue(key, value string) string {
	if IsSensitiveKey(key) {
		return redactedValue
	}
	return RedactString(value)
}

func IsSensitiveKey(key string) bool {
	normalized := strings.ToLower(key)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

func RedactString(value string) string {
	value = telegramTokenRE.ReplaceAllString(value, redactedValue)
	value = dsnRE.ReplaceAllString(value, "${1}"+redactedValue+"${2}")
	value = querySecretRE.ReplaceAllString(value, "${1}"+redactedValue)
	value = authHeaderRE.ReplaceAllString(value, "${1}"+redactedValue)
	return value
}

func RedactedEnvSnapshot(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+RedactKeyValue(key, env[key]))
	}
	return out
}
