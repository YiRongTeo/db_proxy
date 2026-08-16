package config

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Secret handling (user directive 2026-08-17): committed config files carry
// NO passwords — secrets are pulled from a git-ignored .env file (or the
// process environment, which .env populates). LoadDotEnv runs before viper
// load, so the existing ZT_* env-override machinery resolves .env-supplied
// secrets exactly like exported variables.

// dotenvPath returns the env file to load: ZT_ENV_FILE when set (absolute
// or relative to CWD), otherwise ".env" in the working directory (the
// planes run from the repo root, where .env lives).
func dotenvPath() string {
	if p := os.Getenv("ZT_ENV_FILE"); p != "" {
		return p
	}
	return ".env"
}

// LoadDotEnv parses a KEY=VALUE env file (godotenv-style subset: '#' and
// blank lines ignored, optional 'export ' prefix, optional single/double
// quotes, CRLF tolerated) into the PROCESS environment. Variables already
// set in the environment win (process env is authoritative — .env fills the
// gaps). A missing file is a no-op (CI can export variables directly).
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no .env — rely on the process environment
		}
		return fmt.Errorf("open env file %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		raw = strings.TrimPrefix(raw, "export ")
		raw = strings.TrimSpace(raw)
		eq := strings.IndexByte(raw, '=')
		if eq <= 0 {
			return fmt.Errorf("env file %s:%d: malformed line (want KEY=VALUE)", path, line)
		}
		key := strings.TrimSpace(raw[:eq])
		val := strings.TrimSpace(raw[eq+1:])
		if key == "" {
			return fmt.Errorf("env file %s:%d: empty variable name", path, line)
		}
		// Strip one layer of matching quotes.
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
		if _, exists := os.LookupEnv(key); exists {
			continue // process env wins over .env
		}
		if err := os.Setenv(key, val); err != nil {
			return fmt.Errorf("env file %s:%d: set %s: %w", path, line, key, err)
		}
	}
	return sc.Err()
}

// envPlaceholderRe matches ${VAR} placeholders in config values.
var envPlaceholderRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces every ${VAR} placeholder in s with the variable's
// value. An UNSET variable is an error naming it — a credential that
// cannot be resolved must never silently become an empty password
// (explicitly-empty variables are honored: `VAR=` is a real override).
func expandEnv(s string) (string, error) {
	var firstErr error
	out := envPlaceholderRe.ReplaceAllStringFunc(s, func(m string) string {
		if firstErr != nil {
			return m
		}
		name := m[2 : len(m)-1]
		v, ok := os.LookupEnv(name)
		if !ok {
			firstErr = fmt.Errorf("env variable %s referenced by the config is not set (create .env from .env.example)", name)
			return m
		}
		return v
	})
	return out, firstErr
}
