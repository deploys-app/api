package api

// ipInList(<field>, "<list-name>") is a platform-level macro, not engine CEL:
// the parapet engine's CEL surface is pinned (no list variable or function to
// add), so the apiserver expands every reference into a pure ipInCidr || chain
// when it builds the deployer command. The stored form is always the
// unexpanded macro. Anything that compiles expressions with the engine's CEL
// environment (e.g. waf.set's compile validation via parapet pkg/waf) must
// therefore run on the EXPANDED expression — to the engine, ipInList is an
// unknown function.
//
// The scanner is deliberately not a CEL parser (this library has no CEL
// dependency): it skips string literals and comments, then treats every
// remaining occurrence of the reserved token ipInList as a macro that must
// match the full grammar
//
//	ipInList( <ident>(.<ident> | ["<key>"])* , "<list-name>" )
//
// with whitespace allowed between the punctuation. The operand admits no
// calls, parens, commas, or non-string indexes — that is what keeps the macro
// textually unambiguous without a parser. The name is a plain double-quoted
// ReValidName (MinNameLength..MaxNameLength), the same grammar wafList.set
// accepts, so a valid list is always referenceable. This file is mirrored in
// TS for the console; keep the two in sync.

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const wafListMacroToken = "ipInList"

var errWAFListMacroUsage = errors.New("ipInList usage must be `ipInList(<field>, \"<list-name>\")`")

// WAFListRefs returns the sorted, de-duplicated list names referenced by
// ipInList macros in expr. A malformed macro usage returns an error (the same
// structural error Valid() reports).
func WAFListRefs(expr string) ([]string, error) {
	var names []string
	err := scanWAFListMacros(expr, func(_, name string, _, _ int) error {
		names = append(names, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// ExpandWAFListMacros substitutes every ipInList macro in expr using resolve
// (name -> normalized entries, ok). A missing name or malformed usage returns
// an error. Non-macro text is passed through byte-identical.
//
// Each entry expands to one ipInCidr term (a bare IPv4 becomes /32, a bare
// IPv6 /128), joined with " || " and wrapped in parens; the operand text is
// spliced verbatim into each term. An empty list expands to (false) — the
// neutral element for ||, safe in any polarity.
func ExpandWAFListMacros(expr string, resolve func(name string) ([]string, bool)) (string, error) {
	var b strings.Builder
	last := 0
	err := scanWAFListMacros(expr, func(operand, name string, start, end int) error {
		entries, ok := resolve(name)
		if !ok {
			return fmt.Errorf("waf list %q not found", name)
		}
		b.WriteString(expr[last:start])
		if len(entries) == 0 {
			b.WriteString("(false)")
		} else {
			b.WriteByte('(')
			for i, e := range entries {
				cidr, err := wafListEntryCIDR(e)
				if err != nil {
					return err
				}
				if i > 0 {
					b.WriteString(" || ")
				}
				b.WriteString("ipInCidr(")
				b.WriteString(operand)
				b.WriteString(`, "`)
				b.WriteString(cidr)
				b.WriteString(`")`)
			}
			b.WriteByte(')')
		}
		last = end
		return nil
	})
	if err != nil {
		return "", err
	}
	if last == 0 {
		return expr, nil
	}
	b.WriteString(expr[last:])
	return b.String(), nil
}

// wafListEntryCIDR canonicalizes one stored list entry into the CIDR text an
// ipInCidr term carries. Entries are normalized at wafList.set, but expansion
// re-parses and re-renders (masked prefix, canonical address text, bare
// addresses get /32 or /128) so the spliced text is canonical by construction
// — a corrupt-but-parseable entry (unmasked host bits, uppercase IPv6) can
// never reach engine CEL, let alone a broken or meaning-changing one.
func wafListEntryCIDR(e string) (string, error) {
	if strings.Contains(e, "/") {
		prefix, err := netip.ParsePrefix(e)
		if err != nil {
			return "", fmt.Errorf("waf list entry %q invalid", e)
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(e)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("waf list entry %q invalid", e)
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

// scanWAFListMacros walks expr, skipping string literals (all CEL forms:
// "…", '…', triple-quoted, with r/R raw and b/B bytes prefixes in any
// combination, honoring \-escapes in non-raw forms) and // comments, and
// calls emit for every ipInList macro with its operand text, list name, and
// the [start, end) bounds of the whole macro in expr. A reserved-token
// occurrence that does not parse as the full macro grammar is an error, and
// so is the token in member-selector position (x.ipInList(…)): it matches the
// grammar textually but would expand to `x.(…)` — engine-invalid CEL — so it
// must fail structurally instead.
func scanWAFListMacros(expr string, emit func(operand, name string, start, end int) error) error {
	n := len(expr)
	i := 0
	// prevDot: the last significant (non-whitespace, non-comment) byte was
	// '.', i.e. the next identifier is a member selector
	prevDot := false
	for i < n {
		c := expr[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '/' && i+1 < n && expr[i+1] == '/':
			j := strings.IndexByte(expr[i:], '\n')
			if j < 0 {
				return nil
			}
			i += j + 1
		case c == '"' || c == '\'':
			i = skipWAFStringLiteral(expr, i, false)
			prevDot = false
		case isWAFIdentStart(c):
			start := i
			for i < n && isWAFIdentChar(expr[i]) {
				i++
			}
			ident := expr[start:i]
			selector := prevDot
			prevDot = false
			if i < n && (expr[i] == '"' || expr[i] == '\'') && isWAFStringPrefix(ident) {
				i = skipWAFStringLiteral(expr, i, strings.ContainsAny(ident, "rR"))
				continue
			}
			if ident == wafListMacroToken {
				// selector position, or glued to a preceding digit
				// (123ipInList — only digits can abut: a letter/underscore
				// would have merged into one identifier)
				if selector || start > 0 && isWAFIdentChar(expr[start-1]) {
					return errWAFListMacroUsage
				}
				operand, name, end, err := parseWAFListMacro(expr, i)
				if err != nil {
					return err
				}
				if err := emit(operand, name, start, end); err != nil {
					return err
				}
				i = end
			}
		default:
			prevDot = c == '.'
			i++
		}
	}
	return nil
}

func isWAFIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isWAFIdentChar(c byte) bool {
	return isWAFIdentStart(c) || c >= '0' && c <= '9'
}

// isWAFStringPrefix reports whether ident is a CEL string-literal prefix:
// r/R (raw), b/B (bytes), or one of each in either order.
func isWAFStringPrefix(ident string) bool {
	switch len(ident) {
	case 1:
		return strings.ContainsAny(ident, "rRbB")
	case 2:
		return strings.ContainsAny(ident[:1], "rR") && strings.ContainsAny(ident[1:], "bB") ||
			strings.ContainsAny(ident[:1], "bB") && strings.ContainsAny(ident[1:], "rR")
	}
	return false
}

// skipWAFStringLiteral returns the index just past the string literal starting
// at expr[i] (a quote byte). Escapes are honored unless raw. An unterminated
// literal (or a newline inside a single-line form) consumes to end of input —
// the scanner is structural, not a CEL validator; broken CEL is the compiler's
// problem, the scanner only must never find a token inside literal text.
func skipWAFStringLiteral(expr string, i int, raw bool) int {
	n := len(expr)
	q := expr[i]
	if i+2 < n && expr[i+1] == q && expr[i+2] == q {
		// triple-quoted
		i += 3
		for i < n {
			if !raw && expr[i] == '\\' {
				i += 2
				continue
			}
			if expr[i] == q && i+2 < n && expr[i+1] == q && expr[i+2] == q {
				return i + 3
			}
			i++
		}
		return n
	}
	i++
	for i < n {
		switch {
		case !raw && expr[i] == '\\':
			i += 2
		case expr[i] == q:
			return i + 1
		case expr[i] == '\n':
			// single-line literal cannot span a newline; resume scanning after it
			return i + 1
		default:
			i++
		}
	}
	return n
}

// parseWAFListMacro parses one macro immediately after its identifier token
// (i points just past "ipInList") and returns the operand text (verbatim, no
// surrounding whitespace), the list name, and the index just past the closing
// paren.
func parseWAFListMacro(expr string, i int) (operand, name string, end int, err error) {
	n := len(expr)
	skipWS := func(i int) int {
		for i < n {
			switch expr[i] {
			case ' ', '\t', '\n', '\r':
				i++
			default:
				return i
			}
		}
		return i
	}

	i = skipWS(i)
	if i >= n || expr[i] != '(' {
		return "", "", 0, errWAFListMacroUsage
	}
	i = skipWS(i + 1)

	// operand := ident (("." ident) | ("[" dq-string "]"))*  — no inner whitespace
	if i >= n || !isWAFIdentStart(expr[i]) {
		return "", "", 0, errWAFListMacroUsage
	}
	opStart := i
	for i < n && isWAFIdentChar(expr[i]) {
		i++
	}
	for i < n {
		switch expr[i] {
		case '.':
			i++
			if i >= n || !isWAFIdentStart(expr[i]) {
				return "", "", 0, errWAFListMacroUsage
			}
			for i < n && isWAFIdentChar(expr[i]) {
				i++
			}
			continue
		case '[':
			i++
			if i >= n || expr[i] != '"' {
				return "", "", 0, errWAFListMacroUsage
			}
			i++
			for i < n && expr[i] != '"' {
				if expr[i] == '\\' || expr[i] == '\n' || expr[i] == '\r' {
					return "", "", 0, errWAFListMacroUsage
				}
				i++
			}
			if i >= n {
				return "", "", 0, errWAFListMacroUsage
			}
			i++ // closing quote
			if i >= n || expr[i] != ']' {
				return "", "", 0, errWAFListMacroUsage
			}
			i++
			continue
		}
		break
	}
	operand = expr[opStart:i]

	i = skipWS(i)
	if i >= n || expr[i] != ',' {
		return "", "", 0, errWAFListMacroUsage
	}
	i = skipWS(i + 1)

	// name := plain double-quoted ReValidName, no escapes
	if i >= n || expr[i] != '"' {
		return "", "", 0, errWAFListMacroUsage
	}
	i++
	nameStart := i
	for i < n && expr[i] != '"' {
		if expr[i] == '\\' || expr[i] == '\n' || expr[i] == '\r' {
			return "", "", 0, errWAFListMacroUsage
		}
		i++
	}
	if i >= n {
		return "", "", 0, errWAFListMacroUsage
	}
	name = expr[nameStart:i]
	i++ // closing quote
	if len(name) < MinNameLength || len(name) > MaxNameLength || !ReValidName.MatchString(name) {
		return "", "", 0, errWAFListMacroUsage
	}

	i = skipWS(i)
	if i >= n || expr[i] != ')' {
		return "", "", 0, errWAFListMacroUsage
	}
	return operand, name, i + 1, nil
}
