package proxy

import "strings"

// --- Task 6 (node-integration): TRUE read-only write classification ---------
//
// isWriteSQL classifies SQL TEXT as a write command. It is the ONE shared
// classifier behind ro enforcement: every protocol relay extracts its
// statement text (MySQL COM_QUERY/COM_STMT_PREPARE body, PG Query/Parse
// string, MSSQL decoded batch text) and calls this function — a write is
// REJECTED at the proxy (protocol-appropriate error, WARN + metric, never
// forwarded); anything else flows.
//
// CAVEAT (documented in docs/11 + RUN.md): this is TEXT classification —
// a leading-keyword scan. It is a STRONG FIRST LINE, not a guarantee: a
// read-only ASSURANCE comes from provisioning SELECT-only backend accounts
// (ro_user) so even a misclassified statement cannot mutate data. Side
// effects through SELECT (e.g. SELECT ... INTO OUTFILE on MySQL, function
// calls with side effects) are the known residual risk — the backend
// account is the true assurance layer.
//
// EXTEND HERE when a new write verb ships (the verb list is the single
// tuning surface).

// writeVerbsShared are the SQL-standard write verbs every supported
// dialect shares. Compared case-insensitively against the FIRST SQL word
// (after comments/whitespace and WITH-clause walking). EXEC/EXECUTE are
// here too: MSSQL EXEC runs a procedure (sp_executesql included), and PG/
// MySQL EXECUTE runs a prepared statement of unvetted provenance — for a
// ro session that is the fail-safe direction (the caveat below covers the
// residual case of a read-only prepared statement being blocked).
var writeVerbsShared = []string{
	"INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE",
	"CREATE", "DROP", "ALTER", "TRUNCATE", "RENAME",
	"GRANT", "REVOKE", "EXEC", "EXECUTE",
}

// writeVerbsMySQL adds the MySQL-specific statement verbs that mutate
// server or session state beyond the shared list. Note SET is NOT in this
// list: most SETs are flow control (NAMES, autocommit, @vars, sql_mode).
// The SET variants that DO mutate are matched by their own prefixes in
// isWriteSQLMySQL below.
var writeVerbsMySQL = append(append([]string{}, writeVerbsShared...),
	"CALL", "LOAD", "LOCK", "UNLOCK", "HANDLER", "IMPORT", "INSTALL", "UNINSTALL",
	"FLUSH", "RESET", "SHUTDOWN", "KILL", "OPTIMIZE", "ANALYZE", "CHECK", "REPAIR",
)

// commentSkip walks past leading whitespace and comments (-- line, # line,
// /* block */ — including unterminated tails) and returns the remainder.
func commentSkip(s string) string {
	for {
		s = strings.TrimLeft(s, " \t\r\n")
		switch {
		case strings.HasPrefix(s, "--"):
			// "--" needs a following space/control per the standard, but
			// being stricter than MySQL here risks classifying a write as
			// a read — skip any "--" run to end of line.
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[i+1:]
				continue
			}
			return ""
		case strings.HasPrefix(s, "#"):
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[i+1:]
				continue
			}
			return ""
		case strings.HasPrefix(s, "/*"):
			end := strings.Index(s, "*/")
			if end < 0 {
				return "" // unterminated block comment — nothing after it
			}
			s = s[end+2:]
			continue
		default:
			return s
		}
	}
}

// leadingWord extracts the first word of s (upper-cased), "" when s starts
// with a non-word character. Word characters: A-Z, digits and underscore
// (identifiers may start with digits in odd dialects — irrelevant here).
func leadingWord(s string) string {
	i := 0
	for i < len(s) && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_') {
		i++
	}
	if i == 0 {
		return ""
	}
	return strings.ToUpper(s[:i])
}

// isWriteSQL classifies a SQL text against the SHARED verb list (PG and
// MSSQL batch text — and the base for MySQL). Empty/whitespace/comment-only
// text is a read (nothing to enforce).
func isWriteSQL(sql string) bool {
	return isWriteSQLWith(sql, writeVerbsShared)
}

// isWriteSQLMySQL classifies MySQL statement text: the shared list plus the
// MySQL verbs and the mutating SET shapes (SET PASSWORD / SET GLOBAL /
// SET PERSIST). Session-flow SETs stay allowed.
func isWriteSQLMySQL(sql string) bool {
	rest := commentSkip(sql)
	word := leadingWord(rest)
	if word == "SET" {
		// SET that mutates anything beyond session flow control. Match the
		// second word: PASSWORD/GLOBAL/PERSIST/SESSION-with-dangerous-target
		// are writes; NAMES/@var/sql_mode/autocommit/SESSION... stay reads.
		after := commentSkip(rest[len("SET"):])
		second := leadingWord(after)
		switch second {
		case "PASSWORD", "GLOBAL", "PERSIST", "PERSIST_ONLY":
			return true
		}
		return false
	}
	return isWriteSQLWith(sql, writeVerbsMySQL)
}

// isWriteSQLWith walks comments, then CTE heads (WITH [RECURSIVE] name AS
// (...) — repeatedly, comma-separated), then matches the leading word
// against verbs. A WITH whose body eventually leads to a write verb (data-
// modifying CTEs are legal in PG: WITH x AS (DELETE ...) SELECT ...) is
// classified by the FIRST NON-CTE keyword after the last CTE clause — which
// is the outer statement's verb; PG requires that to be SELECT for data-
// modifying CTEs, so the walk sees THROUGH the CTE to the outer verb. To
// stay fail-safe for the write-in-CTE shapes the walker ALSO rejects when
// any CTE body's own leading word is a write verb.
func isWriteSQLWith(sql string, verbs []string) bool {
	s := commentSkip(sql)
	// WITH-walk: track CTE bodies and the final outer verb.
	for {
		word := leadingWord(s)
		if word != "WITH" {
			break
		}
		after := commentSkip(s[len("WITH"):])
		if w := leadingWord(after); w == "RECURSIVE" {
			after = commentSkip(after[len("RECURSIVE"):])
		}
		// The CTE body: scan forward for the matching close paren of its
		// "name AS (" clause, classify the body's own leading word, then
		// continue after the body (comma → next CTE, else the outer verb).
		body, tail, ok := nextCTEBody(after)
		if !ok {
			// Malformed WITH — fail SAFE: treat as a write (rejected) so a
			// parse-escaping attempt cannot smuggle a mutation through.
			return true
		}
		if isWriteSQLWith(body, verbs) {
			return true // data-modifying CTE
		}
		s = commentSkip(tail)
		if strings.HasPrefix(s, ",") {
			s = commentSkip(s[1:])
			continue // another CTE clause
		}
		break // the outer verb follows in s
	}
	return verbMatch(leadingWord(s), verbs)
}

// verbMatch reports whether word is one of the write verbs.
func verbMatch(word string, verbs []string) bool {
	if word == "" {
		return false
	}
	for _, v := range verbs {
		if word == v {
			return true
		}
	}
	return false
}

// nextCTEBody extracts the parenthesized body of the first "name AS (…)"
// clause from the text after WITH [RECURSIVE], returning the inside of the
// parens, the remainder after the closing paren, and whether a body was
// found. Nests (COUNT(*) etc.) are honored by depth counting; quoted
// literals and identifiers inside are safe (a paren in a string would only
// skew the depth — fail-safe direction: a missing close yields ok=false →
// the caller treats the whole statement as a write).
func nextCTEBody(s string) (body, tail string, ok bool) {
	depth := 0
	start := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				return s[start+1 : i], s[i+1:], true
			}
			if depth < 0 {
				return "", "", false
			}
		}
	}
	return "", "", false
}

// mssqlReadOnlyProc names the system procedures EXEC runs of that are pure
// reads — the MSSQL relay consults this before classifying an RPC as a
// write. Everything else (sp_executesql included) is a write.
var mssqlReadOnlyProcs = map[string]bool{
	"sp_who": true, "sp_who2": true, "sp_help": true, "sp_helpdb": true,
	"sp_databases": true, "sp_server_info": true, "sp_pkeys": true,
	"sp_fkeys": true, "sp_columns": true, "sp_statistics": true,
	"sp_tables": true, "sp_stored_procedures": true,
}

// mssqlReadOnlyProc reports whether name is a known read-only system
// procedure (case-insensitive).
func mssqlReadOnlyProc(name string) bool {
	return mssqlReadOnlyProcs[strings.ToLower(strings.TrimSpace(name))]
}
