//! In-house RFC 8785 (JCS) canonicalization with a fail-closed value domain.
//!
//! This is the most security-critical unit in MTCI: the descriptor/catalog hash
//! depends on a byte-identical preimage. We therefore do NOT depend on an
//! external JCS crate — RFC 8785 canonicalization is implemented here so the
//! preimage is fully auditable, and pinned by committed vectors.
//!
//! # JCS domain (every violation => [`IntegrityError::Canonicalization`])
//! MTCI implements **full RFC 8785 / JCS over I-JSON**: every JSON number is an
//! IEEE-754 double, and any FINITE double is accepted and serialized via the
//! ECMAScript `Number::toString` algorithm (RFC 8785 §3.2.2.3). The following
//! fail closed:
//! 1. **Duplicate object member names** within any object are rejected. We parse
//!    the raw bytes with our own value model that surfaces duplicates — we do NOT
//!    rely on `serde_json::Value`/`Map`, which silently keeps the last duplicate.
//! 2. **Invalid UTF-8** in the input is rejected before parsing; **unpaired
//!    surrogates** expressed via `\uXXXX` escapes are rejected during string
//!    parsing.
//! 3. **Non-finite numbers** (NaN, ±Infinity) and **out-of-double-domain** values
//!    — numeric tokens that overflow to ±Infinity or underflow to zero while
//!    carrying a nonzero significand (e.g. `1e400`, `1e-400`) — are rejected.
//!    Leading-zero integers (`01`), a leading `+`, and malformed numeric tokens
//!    are rejected.
//! 4. **No Unicode normalization / no parser repair** — code points pass through
//!    unchanged.
//!
//! Unlike MCP-S's canonicalizer — which intentionally uses an INTEGER-ONLY safety
//! profile for the signed protocol envelopes whose numeric domain it controls —
//! MTCI implements full RFC 8785/JCS because tool descriptors carry arbitrary
//! JSON Schema (finite floats like `minimum`/`multipleOf`). The two domains are
//! deliberately different and MUST NOT be unified: doing so would either
//! over-restrict MTCI or weaken MCP-S. MTCI canonicalizes numbers as IEEE-754
//! doubles and does NOT preserve arbitrary decimal precision; descriptors needing
//! exact high-precision decimals should encode them as strings (RFC 8785 I-JSON).
//!
//! # Canonical output (RFC 8785)
//! - Object members sorted by member name using UTF-16 code-unit ordering.
//! - Numbers serialized via ECMAScript `Number::toString` (finite doubles); `-0`
//!   => `0`, shortest round-trip significand, no leading `+`.
//! - Strings escape only `"`, `\`, and control chars U+0000–U+001F (short forms
//!   `\b \t \n \f \r` where applicable, else `\u00xx` lowercase hex). All other
//!   code points are emitted as literal UTF-8 bytes — never `\u`-escaped.
//! - Arrays in order; no insignificant whitespace anywhere; `true`/`false`/`null`
//!   as literals.

use crate::IntegrityError;

/// The single, uniform canonicalization failure raised by every JCS-domain
/// violation on this path. Centralizing it keeps the fail-closed contract
/// auditable: canonicalization never falls back to best-effort output.
fn canon_fail() -> IntegrityError {
    IntegrityError::Canonicalization("value outside the JCS domain (RFC 8785)".to_string())
}

/// Maximum container-nesting depth accepted by either recursive parse path
/// (MCPS-073). Matches `serde_json`'s default `recursion_limit` so the raw-bytes
/// parser and the serde-backed verify path reject at the same depth, preserving
/// the raw-path/value-path agreement invariant. Exceeding it fails closed via
/// [`IntegrityError::Canonicalization`] rather than overflowing the stack.
const MAX_PARSE_DEPTH: usize = 128;

/// A validated, JCS-safe JSON value. Constructed only by [`parse`], which
/// enforces the JCS-safe domain, so any `JcsValue` is guaranteed canonicalizable.
///
/// Object members retain insertion order here (a `Vec` of pairs); the canonical
/// serializer sorts them by UTF-16 code-unit order at emit time.
#[derive(Debug, Clone, PartialEq)]
pub enum JcsValue {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// A JSON number, held as a FINITE IEEE-754 double per RFC 8785 / I-JSON.
    /// Non-finite values (NaN, ±Infinity) are never produced by the parsers and
    /// are rejected at serialization time on the public hand-constructible path.
    Number(f64),
    /// A JSON string (already validated UTF-8, surrogate-paired).
    String(String),
    /// A JSON array.
    Array(Vec<JcsValue>),
    /// A JSON object. Keys are unique (duplicates rejected at parse time).
    Object(Vec<(String, JcsValue)>),
}

/// Parse raw JSON bytes, validate against the JCS-safe domain, and emit RFC 8785
/// canonical UTF-8 bytes.
///
/// On any domain violation (duplicate keys, invalid UTF-8, unpaired surrogate,
/// non-finite / out-of-double-domain number, malformed JSON) returns
/// [`IntegrityError::Canonicalization`].
pub fn canonicalize(input: &[u8]) -> Result<Vec<u8>, IntegrityError> {
    let value = parse(input)?;
    canonicalize_value(&value)
}

/// Parse raw JSON bytes into a validated [`JcsValue`] tree, enforcing the full
/// JCS-safe domain (including duplicate-key detection, which MUST happen on this
/// raw-bytes path — `serde_json::Value` cannot represent duplicate keys).
pub fn parse(input: &[u8]) -> Result<JcsValue, IntegrityError> {
    // (2) Reject invalid UTF-8 up front.
    let text = std::str::from_utf8(input).map_err(|_| canon_fail())?;
    let mut parser = Parser::new(text);
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if !parser.at_end() {
        // Trailing non-whitespace content.
        return Err(canon_fail());
    }
    Ok(value)
}

/// Emit RFC 8785 canonical UTF-8 bytes for an already-validated value tree.
///
/// `JcsValue` is a PUBLIC, hand-constructible enum (its container variants are
/// re-exported at the crate root), so an external caller can build a value tree
/// nested far deeper than any [`parse`]-produced tree (which is already bounded
/// by [`MAX_PARSE_DEPTH`]). The serializer therefore enforces the SAME depth
/// bound itself and fails closed via [`IntegrityError::Canonicalization`]
/// rather than overflowing the stack (MCPS-092). In-crate callers always pass a
/// value at depth ≤ [`MAX_PARSE_DEPTH`], so this only ever rejects adversarial
/// externally-constructed trees.
pub fn canonicalize_value(value: &JcsValue) -> Result<Vec<u8>, IntegrityError> {
    let mut out = String::new();
    write_value(value, 0, &mut out)?;
    Ok(out.into_bytes())
}

/// Canonicalize an already-parsed [`serde_json::Value`] for the later signing
/// layer (MCPS-005) and pipeline (MCPS-008), e.g. after removing
/// `signature.value` from the JSON-RPC object.
///
/// NOTE: `serde_json::Value` cannot represent duplicate object keys (its `Map`
/// silently keeps the last), so this path CANNOT detect duplicate members. The
/// duplicate-key check is therefore the responsibility of the raw-bytes
/// [`parse`]/[`canonicalize`] path, which MUST be run on the original wire bytes
/// before any `serde_json::Value` is derived. This helper still enforces the
/// rest of the JCS domain (finite numbers only, valid strings).
pub fn canonicalize_json_value(value: &serde_json::Value) -> Result<Vec<u8>, IntegrityError> {
    let jcs = from_serde_value(value)?;
    canonicalize_value(&jcs)
}

/// Convert a `serde_json::Value` into a validated [`JcsValue`], enforcing the
/// finite-double number rule. Cannot detect duplicate keys (see
/// [`canonicalize_json_value`]).
fn from_serde_value(value: &serde_json::Value) -> Result<JcsValue, IntegrityError> {
    // Bound recursion identically to the raw-bytes path (MCPS-073). depth counts
    // container nesting; the public entry starts at 0.
    from_serde_value_at(value, 0)
}

/// Depth-bounded core of [`from_serde_value`]. `depth` is the container-nesting
/// level of `value`; recursing into a container's children passes `depth + 1`.
fn from_serde_value_at(value: &serde_json::Value, depth: usize) -> Result<JcsValue, IntegrityError> {
    match value {
        serde_json::Value::Null => Ok(JcsValue::Null),
        serde_json::Value::Bool(b) => Ok(JcsValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            // RFC 8785 / I-JSON: every JSON number is an IEEE-754 double. serde_json
            // (without arbitrary_precision) cannot hold NaN/Inf, and as_f64 of a large
            // integer yields its double approximation — the I-JSON stance, accepted.
            let f = n.as_f64().ok_or_else(canon_fail)?;
            if !f.is_finite() {
                return Err(canon_fail());
            }
            Ok(JcsValue::Number(f))
        }
        serde_json::Value::String(s) => Ok(JcsValue::String(s.clone())),
        serde_json::Value::Array(items) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(canon_fail());
            }
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(from_serde_value_at(item, depth + 1)?);
            }
            Ok(JcsValue::Array(out))
        }
        serde_json::Value::Object(map) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(canon_fail());
            }
            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                out.push((k.clone(), from_serde_value_at(v, depth + 1)?));
            }
            Ok(JcsValue::Object(out))
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical serialization (RFC 8785 output rules).
// ---------------------------------------------------------------------------

/// Recursively emit canonical bytes for `value`. `depth` is the container-nesting
/// level of `value`; recursing into a container's children passes `depth + 1`.
///
/// The bound mirrors the two parse paths ([`Parser::parse_value`] and
/// [`from_serde_value_at`]): a container at or beyond [`MAX_PARSE_DEPTH`] fails
/// closed via [`IntegrityError::Canonicalization`] instead of overflowing the
/// stack. This guards the PUBLIC, hand-constructible [`JcsValue`] surface
/// (MCPS-092) — only Array/Object add depth, so non-container leaves never trip
/// it.
fn write_value(value: &JcsValue, depth: usize, out: &mut String) -> Result<(), IntegrityError> {
    match value {
        JcsValue::Null => out.push_str("null"),
        JcsValue::Bool(true) => out.push_str("true"),
        JcsValue::Bool(false) => out.push_str("false"),
        JcsValue::Number(x) => write_number(*x, out)?,
        JcsValue::String(s) => write_string(s, out),
        JcsValue::Array(items) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(canon_fail());
            }
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_value(item, depth + 1, out)?;
            }
            out.push(']');
        }
        JcsValue::Object(members) => {
            if depth >= MAX_PARSE_DEPTH {
                return Err(canon_fail());
            }
            // Sort members by member name using UTF-16 code-unit ordering.
            let mut sorted: Vec<&(String, JcsValue)> = members.iter().collect();
            sorted.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
            // Re-enforce the JCS no-duplicate-key invariant on the PUBLIC,
            // hand-constructible `JcsValue` surface, mirroring the depth-bound
            // treatment above (MCPS-092). `parse()`/`from_serde_value` cannot
            // produce duplicates, but a caller hand-building
            // `JcsValue::Object(vec![("a", _), ("a", _)])` otherwise emits the
            // key twice instead of failing closed. Sorting by key (stability is
            // immaterial here) puts equal keys adjacent, so a single adjacent-pair
            // scan detects them.
            if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(canon_fail());
            }
            out.push('{');
            for (idx, (key, val)) in sorted.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(val, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Serialize a finite IEEE-754 double per RFC 8785 §3.2.2.3 (the ECMAScript
/// `Number::toString` algorithm). Rust's `format!("{:e}", _)` supplies the
/// shortest round-trip significand and decimal exponent; this routine then
/// applies the ECMAScript positional/exponential formatting rules.
///
/// Non-finite values (which the parsers never produce, but a hand-built
/// `JcsValue::Number(f64::NAN)` could carry) fail closed.
fn write_number(x: f64, out: &mut String) -> Result<(), IntegrityError> {
    if !x.is_finite() {
        return Err(canon_fail());
    }
    if x == 0.0 {
        // Covers both +0.0 and -0.0 => "0".
        out.push('0');
        return Ok(());
    }
    if x < 0.0 {
        out.push('-');
    }
    // Rust shortest round-trip: "<mant>e<exp>", mant first digit nonzero,
    // no trailing zeros.
    let sci = format!("{:e}", x.abs());
    let (mant, exp_str) = sci.split_once('e').ok_or_else(canon_fail)?;
    let exp: i32 = exp_str.parse().map_err(|_| canon_fail())?;
    // Significand digits only (drop the '.'); ASCII, so byte indexing is safe.
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1; // position of the decimal point relative to `digits`.
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.push_str(&"0".repeat((n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[0..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-n) as usize));
        out.push_str(&digits);
    } else {
        // n > 21 or n <= -6 => exponential form.
        let mant2 = if k == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[0..1], &digits[1..])
        };
        let e = n - 1;
        let esign = if e >= 0 { "+" } else { "-" };
        out.push_str(&mant2);
        out.push('e');
        out.push_str(esign);
        out.push_str(&e.abs().to_string());
    }
    Ok(())
}

/// Escape per RFC 8785: only `"`, `\`, and control chars U+0000–U+001F; short
/// forms where applicable, else `\u00xx` lowercase hex. Everything else literal.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) <= 0x1F => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two strings by their UTF-16 code-unit sequences (RFC 8785 ordering).
fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            },
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal, fail-closed JSON parser over a validated UTF-8 &str.
// ---------------------------------------------------------------------------

/// A character-level JSON parser. Operates over chars (the input is already
/// validated UTF-8) and enforces the JCS-safe domain during parsing.
struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    /// Current container-nesting depth (only objects/arrays add depth). Bounded
    /// by [`MAX_PARSE_DEPTH`] so untrusted deep nesting fails closed instead of
    /// overflowing the stack (MCPS-073).
    depth: usize,
    _marker: std::marker::PhantomData<&'a str>,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Parser {
            chars: text.chars().collect(),
            pos: 0,
            depth: 0,
            _marker: std::marker::PhantomData,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        // RFC 8259 insignificant whitespace: space, tab, LF, CR.
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), IntegrityError> {
        match self.bump() {
            Some(c) if c == expected => Ok(()),
            _ => Err(canon_fail()),
        }
    }

    fn parse_value(&mut self) -> Result<JcsValue, IntegrityError> {
        match self.peek() {
            // Containers add nesting depth; bound it so deeply-nested untrusted
            // input fails closed rather than overflowing the stack (MCPS-073).
            Some('{') | Some('[') => {
                if self.depth >= MAX_PARSE_DEPTH {
                    return Err(canon_fail());
                }
                self.depth += 1;
                let result = if self.peek() == Some('{') {
                    self.parse_object()
                } else {
                    self.parse_array()
                };
                self.depth -= 1;
                result
            }
            Some('"') => Ok(JcsValue::String(self.parse_string()?)),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(canon_fail()),
        }
    }

    fn parse_literal(&mut self, literal: &str) -> Result<(), IntegrityError> {
        for expected in literal.chars() {
            self.expect(expected)?;
        }
        Ok(())
    }

    fn parse_bool(&mut self) -> Result<JcsValue, IntegrityError> {
        match self.peek() {
            Some('t') => {
                self.parse_literal("true")?;
                Ok(JcsValue::Bool(true))
            }
            Some('f') => {
                self.parse_literal("false")?;
                Ok(JcsValue::Bool(false))
            }
            _ => Err(canon_fail()),
        }
    }

    fn parse_null(&mut self) -> Result<JcsValue, IntegrityError> {
        self.parse_literal("null")?;
        Ok(JcsValue::Null)
    }

    fn parse_object(&mut self) -> Result<JcsValue, IntegrityError> {
        self.expect('{')?;
        self.skip_ws();
        let mut members: Vec<(String, JcsValue)> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(JcsValue::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(canon_fail());
            }
            let key = self.parse_string()?;
            // (1) Duplicate member name within this object => reject.
            if !seen.insert(key.clone()) {
                return Err(canon_fail());
            }
            self.skip_ws();
            self.expect(':')?;
            self.skip_ws();
            let value = self.parse_value()?;
            members.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err(canon_fail()),
            }
        }
        Ok(JcsValue::Object(members))
    }

    fn parse_array(&mut self) -> Result<JcsValue, IntegrityError> {
        self.expect('[')?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(']') {
            self.bump();
            return Ok(JcsValue::Array(items));
        }
        loop {
            self.skip_ws();
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err(canon_fail()),
            }
        }
        Ok(JcsValue::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, IntegrityError> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(canon_fail()),
                Some('"') => break,
                Some('\\') => {
                    let esc = self.bump().ok_or(canon_fail())?;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let cp = self.parse_unicode_escape()?;
                            out.push(cp);
                        }
                        _ => return Err(canon_fail()),
                    }
                }
                Some(c) => {
                    // Reject raw control characters U+0000–U+001F in strings
                    // (must be escaped in valid JSON).
                    if (c as u32) <= 0x1F {
                        return Err(canon_fail());
                    }
                    out.push(c);
                }
            }
        }
        Ok(out)
    }

    /// Parse a `\uXXXX` escape (the `\u` already consumed), handling surrogate
    /// pairs and rejecting unpaired surrogates.
    fn parse_unicode_escape(&mut self) -> Result<char, IntegrityError> {
        let first = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&first) {
            // High surrogate: a low surrogate MUST follow via `\uXXXX`.
            if self.bump() != Some('\\') {
                return Err(canon_fail());
            }
            if self.bump() != Some('u') {
                return Err(canon_fail());
            }
            let second = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(canon_fail());
            }
            let combined =
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            char::from_u32(combined).ok_or(canon_fail())
        } else if (0xDC00..=0xDFFF).contains(&first) {
            // Lone low surrogate => unpaired => reject.
            Err(canon_fail())
        } else {
            char::from_u32(first).ok_or(canon_fail())
        }
    }

    fn read_hex4(&mut self) -> Result<u32, IntegrityError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self.bump().ok_or(canon_fail())?;
            let digit = c.to_digit(16).ok_or(canon_fail())?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    /// Parse a JSON number over the FULL RFC 8259 / I-JSON grammar and accept any
    /// finite IEEE-754 double (RFC 8785 number domain). The grammar is: optional
    /// `-`, integer part (`0` alone OR `[1-9][0-9]*` — leading zeros rejected),
    /// optional fraction `. [0-9]+`, optional exponent `[eE][+-]?[0-9]+`. A leading
    /// `+` is rejected (the grammar only consumes `-`).
    ///
    /// Out-of-double-domain tokens fail closed: a token that overflows to ±Infinity,
    /// or one that underflows to `0.0` while its significand carries a nonzero digit
    /// (e.g. `1e-400`), is rejected.
    fn parse_number(&mut self) -> Result<JcsValue, IntegrityError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        // Integer part: a single 0, or [1-9][0-9]* (no leading zeros).
        match self.peek() {
            Some('0') => {
                self.bump();
            }
            Some(c) if ('1'..='9').contains(&c) => {
                self.bump();
                while let Some(d) = self.peek() {
                    if d.is_ascii_digit() {
                        self.bump();
                    } else {
                        break;
                    }
                }
            }
            _ => return Err(canon_fail()),
        }
        // Optional fraction: '.' followed by one or more digits.
        if self.peek() == Some('.') {
            self.bump();
            let mut saw_digit = false;
            while let Some(d) = self.peek() {
                if d.is_ascii_digit() {
                    self.bump();
                    saw_digit = true;
                } else {
                    break;
                }
            }
            if !saw_digit {
                return Err(canon_fail());
            }
        }
        // Optional exponent: [eE], optional sign, one or more digits.
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.bump();
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.bump();
            }
            let mut saw_digit = false;
            while let Some(d) = self.peek() {
                if d.is_ascii_digit() {
                    self.bump();
                    saw_digit = true;
                } else {
                    break;
                }
            }
            if !saw_digit {
                return Err(canon_fail());
            }
        }
        let token: String = self.chars[start..self.pos].iter().collect();
        let parsed: f64 = token.parse().map_err(|_| canon_fail())?;
        if !parsed.is_finite() {
            // Overflow to ±Infinity (e.g. `1e400`).
            return Err(canon_fail());
        }
        if parsed == 0.0 && token.bytes().any(|b| (b'1'..=b'9').contains(&b)) {
            // Underflow to zero while the significand carries a nonzero digit
            // (e.g. `1e-400`): outside the representable double domain.
            return Err(canon_fail());
        }
        Ok(JcsValue::Number(parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::canonicalize;
    use super::canonicalize_json_value;
    use super::canonicalize_value;
    use super::canon_fail;
    use super::JcsValue;
    use super::MAX_PARSE_DEPTH;
    use crate::IntegrityError;

    fn canon_str(input: &str) -> Result<String, IntegrityError> {
        canonicalize(input.as_bytes()).map(|b| String::from_utf8(b).expect("utf8"))
    }

    // ---- JCS domain: duplicate keys / surrogates / UTF-8 / large-ids ----

    #[test]
    fn jcs_01_duplicate_key_rejected() {
        let err = canonicalize(br#"{"a":1,"a":2}"#).unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn jcs_01_nested_duplicate_key_rejected() {
        let err = canonicalize(br#"{"outer":{"a":1,"a":2}}"#).unwrap_err();
        assert_eq!(err, canon_fail());
    }

    // ---- RFC 8785 finite-number vectors (full JCS, not integer-only) ----

    #[test]
    fn rfc8785_number_vectors() {
        // The canonical decimal/exponent forms below are RFC-8785-correct and MUST
        // match exactly; a mismatch means write_number is wrong.
        assert_eq!(canon_str("4.50").unwrap(), "4.5");
        assert_eq!(canon_str("0.002").unwrap(), "0.002");
        assert_eq!(canon_str("1e30").unwrap(), "1e+30");
        assert_eq!(canon_str("1e-27").unwrap(), "1e-27");
        assert_eq!(canon_str("333333333.33333329").unwrap(), "333333333.3333333");
        assert_eq!(canon_str("100").unwrap(), "100");
        assert_eq!(canon_str("0").unwrap(), "0");
        assert_eq!(canon_str("-0").unwrap(), "0");
    }

    #[test]
    fn non_integer_number_accepted() {
        // Was rejected under the integer-only profile; now accepted (full JCS).
        assert_eq!(canon_str("1.5").unwrap(), "1.5");
    }

    #[test]
    fn exponent_number_accepted_as_ecmascript_form() {
        // Was rejected under the integer-only profile; now accepted and rendered
        // in ECMAScript Number::toString form.
        assert_eq!(canon_str("1e3").unwrap(), "1000");
        assert_eq!(canon_str("1E3").unwrap(), "1000");
    }

    #[test]
    fn large_integer_accepted_as_double() {
        // 2^53 + 1 = 9007199254740993 is NOT representable as a double; per I-JSON
        // it is accepted and canonicalizes to its nearest double, 2^53 =
        // 9007199254740992 (pinned from the actual ECMAScript output).
        assert_eq!(canon_str("9007199254740993").unwrap(), "9007199254740992");
        // 2^53 - 1 round-trips exactly.
        assert_eq!(canon_str("9007199254740991").unwrap(), "9007199254740991");
        assert_eq!(canon_str("-9007199254740991").unwrap(), "-9007199254740991");
    }

    #[test]
    fn json_schema_decimals_accepted() {
        assert_eq!(canon_str(r#"{"minimum":0.5}"#).unwrap(), r#"{"minimum":0.5}"#);
        assert_eq!(
            canon_str(r#"{"multipleOf":0.1}"#).unwrap(),
            r#"{"multipleOf":0.1}"#
        );
    }

    #[test]
    fn realistic_descriptor_with_floats_canonicalizes_sorted() {
        let input = r#"{"inputSchema":{"properties":{"temp":{"type":"number","default":0.5,"minimum":-1.5}}},"name":"x"}"#;
        let out = canon_str(input);
        assert!(out.is_ok());
        // Top-level keys are already sorted (inputSchema < name); the nested
        // descriptor-property keys sort to default < minimum < type.
        assert_eq!(
            out.unwrap(),
            r#"{"inputSchema":{"properties":{"temp":{"default":0.5,"minimum":-1.5,"type":"number"}}},"name":"x"}"#
        );
    }

    #[test]
    fn number_overflow_rejected() {
        assert!(canonicalize(b"1e400").is_err());
    }

    #[test]
    fn number_underflow_rejected() {
        assert!(canonicalize(b"1e-400").is_err());
    }

    #[test]
    fn constructed_non_finite_number_rejected() {
        assert!(canonicalize_value(&JcsValue::Number(f64::NAN)).is_err());
        assert!(canonicalize_value(&JcsValue::Number(f64::INFINITY)).is_err());
        assert!(canonicalize_value(&JcsValue::Number(f64::NEG_INFINITY)).is_err());
    }

    #[test]
    fn jcs_06_unpaired_high_surrogate_rejected() {
        let err = canonicalize(br#""\uD800""#).unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn jcs_06_unpaired_low_surrogate_rejected() {
        let err = canonicalize(br#""\uDC00""#).unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn valid_surrogate_pair_accepted() {
        // 😀 = U+1F600 GRINNING FACE; must decode and emit literal UTF-8.
        let out = canon_str(r#""😀""#).unwrap();
        assert_eq!(out, "\"\u{1F600}\"");
    }

    #[test]
    fn jcs_07_invalid_utf8_rejected() {
        // 0xFF is never valid UTF-8.
        let err = canonicalize(&[0x22, 0xFF, 0x22]).unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn jcs_08_large_id_as_string_ok() {
        let out = canon_str(r#"{"id":"9007199254740993"}"#).unwrap();
        assert_eq!(out, r#"{"id":"9007199254740993"}"#);
    }

    // ---- Golden canonicalization vectors ----

    #[test]
    fn golden_object_keys_sorted() {
        assert_eq!(canon_str(r#"{"b":1,"a":2}"#).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn golden_nested_object_keys_sorted() {
        let input = r#"{"z":{"y":1,"x":2},"a":3}"#;
        assert_eq!(canon_str(input).unwrap(), r#"{"a":3,"z":{"x":2,"y":1}}"#);
    }

    #[test]
    fn golden_non_ascii_char_stays_literal() {
        // "é" (U+00E9) must NOT be \u-escaped; emitted as literal UTF-8.
        let out = canonicalize(r#"{"name":"é"}"#.as_bytes()).unwrap();
        assert_eq!(out, r#"{"name":"é"}"#.as_bytes());
        // Must contain the raw 2-byte UTF-8 for é (0xC3 0xA9), and no "\\u".
        assert!(out.windows(2).any(|w| w == [0xC3, 0xA9]));
        assert!(!String::from_utf8(out).unwrap().contains("\\u"));
    }

    #[test]
    fn golden_control_char_tab_becomes_short_escape() {
        // A tab escaped in the input as \t canonicalizes to the short form \t.
        let out = canon_str(r#"{"k":"a\tb"}"#).unwrap();
        assert_eq!(out, r#"{"k":"a\tb"}"#);
    }

    #[test]
    fn raw_control_char_in_string_rejected() {
        // A literal (unescaped) tab byte inside a JSON string is invalid JSON.
        let err = canonicalize(b"\"a\tb\"").unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn golden_other_control_char_lowercase_hex() {
        // U+0001 has no short form; input carries it as the JSON escape
        // backslash-u-0001 and canonicalizes to lowercase-hex \u0001.
        // Bytes are built explicitly so no raw control byte is present.
        let bs = b'\\';
        let q = b'"';
        let input = [q, bs, b'u', b'0', b'0', b'0', b'1', q];
        let out = canonicalize(&input).unwrap();
        assert_eq!(out, &[q, bs, b'u', b'0', b'0', b'0', b'1', q]);
    }

    #[test]
    fn golden_escaped_quote_and_backslash() {
        let out = canon_str(r#""a\"b\\c""#).unwrap();
        assert_eq!(out, r#""a\"b\\c""#);
    }

    #[test]
    fn golden_negative_zero_normalized() {
        assert_eq!(canon_str("-0").unwrap(), "0");
        assert_eq!(canon_str(r#"{"v":-0}"#).unwrap(), r#"{"v":0}"#);
    }

    #[test]
    fn golden_literals_and_array_no_whitespace() {
        let input = r#"  [ true , false , null , 1 , "x" ]  "#;
        assert_eq!(canon_str(input).unwrap(), r#"[true,false,null,1,"x"]"#);
    }

    #[test]
    fn golden_empty_object_and_array() {
        assert_eq!(canon_str("{}").unwrap(), "{}");
        assert_eq!(canon_str("[]").unwrap(), "[]");
    }

    #[test]
    fn golden_whitespace_insignificant() {
        let input = "{\n  \"b\" : 2 ,\n  \"a\" : 1\n}";
        assert_eq!(canon_str(input).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn leading_zero_integer_rejected() {
        let err = canonicalize(b"01").unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn plus_sign_rejected() {
        let err = canonicalize(b"+1").unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn trailing_garbage_rejected() {
        let err = canonicalize(br#"{"a":1} extra"#).unwrap_err();
        assert_eq!(err, canon_fail());
    }

    #[test]
    fn trailing_comma_rejected() {
        assert_eq!(canonicalize(br#"{"a":1,}"#).unwrap_err(), canon_fail());
        assert_eq!(canonicalize(br#"[1,2,]"#).unwrap_err(), canon_fail());
    }

    // ---- Determinism ----

    #[test]
    fn determinism_canonicalize_is_idempotent() {
        let input = r#"{"b":[3,2,1],"a":{"d":1,"c":"é\t"},"id":"123"}"#;
        let once = canonicalize(input.as_bytes()).unwrap();
        let twice = canonicalize(&once).unwrap();
        assert_eq!(once, twice);
    }

    // ---- serde_json::Value helper (for MCPS-005/008) ----

    #[test]
    fn json_value_helper_canonicalizes_and_sorts() {
        let v: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        let out = canonicalize_json_value(&v).unwrap();
        assert_eq!(out, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn json_value_helper_accepts_float() {
        // Full JCS: a fractional value is accepted on the serde path too.
        let v: serde_json::Value = serde_json::from_str("1.5").unwrap();
        assert_eq!(canonicalize_json_value(&v).unwrap(), b"1.5");
    }

    #[test]
    fn json_value_helper_matches_raw_path_for_valid_float_input() {
        // A float-containing input must canonicalize identically via the raw-bytes
        // path and the serde_json::Value path.
        let input = r#"{"z":1,"a":{"y":"é","x":0.5},"id":"9007199254740993"}"#;
        let raw = canonicalize(input.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_str(input).unwrap();
        let via_value = canonicalize_json_value(&v).unwrap();
        assert_eq!(raw, via_value);
    }

    #[test]
    fn json_value_helper_matches_raw_path_for_valid_input() {
        let input = r#"{"z":1,"a":{"y":"é","x":2},"id":"9007199254740993"}"#;
        let raw = canonicalize(input.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_str(input).unwrap();
        let via_value = canonicalize_json_value(&v).unwrap();
        assert_eq!(raw, via_value);
    }

    // ---- Recursion-depth bound (MCPS-073) ----
    //
    // Deeply-nested untrusted JSON must fail closed via CanonicalizationFailed
    // rather than overflow the stack. The bound matches serde_json's default
    // recursion_limit (128) so the raw-bytes parser and the serde-backed verify
    // path reject at the same depth, preserving raw-path/value-path agreement.

    #[test]
    fn parse_depth_limit_rejects_over_max() {
        // MAX_PARSE_DEPTH + 1 = 129 nested arrays must be rejected.
        let s = "[".repeat(MAX_PARSE_DEPTH + 1) + &"]".repeat(MAX_PARSE_DEPTH + 1);
        assert_eq!(
            canonicalize(s.as_bytes()).unwrap_err(),
            canon_fail()
        );
    }

    #[test]
    fn parse_depth_limit_allows_exactly_max() {
        // Exactly MAX_PARSE_DEPTH = 128 nested arrays is the inclusive boundary.
        let s = "[".repeat(MAX_PARSE_DEPTH) + &"]".repeat(MAX_PARSE_DEPTH);
        canon_str(&s).expect("depth at the inclusive boundary must canonicalize");
    }

    #[test]
    fn parse_depth_limit_rejects_nested_objects() {
        // MAX_PARSE_DEPTH + 1 = 129 nested single-member objects must be rejected
        // on the object path. The input is well-formed JSON
        // (`{"a":{"a":...{"a":1}...}}`); its ONLY problem is nesting depth, so the
        // rejection genuinely exercises the object recursion-depth bound rather
        // than tripping on a malformed token.
        let n = MAX_PARSE_DEPTH + 1;
        let s = "{\"a\":".repeat(n) + "1" + &"}".repeat(n);
        assert_eq!(
            canonicalize(s.as_bytes()).unwrap_err(),
            canon_fail()
        );
    }

    #[test]
    fn parse_depth_limit_allows_exactly_max_objects() {
        // Exactly MAX_PARSE_DEPTH = 128 nested single-member objects is the
        // inclusive boundary: well-formed JSON within the bound must canonicalize.
        // Paired with `parse_depth_limit_rejects_nested_objects`, this proves the
        // rejection above is due to depth, not malformedness.
        let n = MAX_PARSE_DEPTH;
        let s = "{\"a\":".repeat(n) + "1" + &"}".repeat(n);
        canon_str(&s).expect("object depth at the inclusive boundary must canonicalize");
    }

    #[test]
    fn canonicalize_json_value_rejects_over_max_depth() {
        // Build a 129-deep serde_json::Value programmatically (no parsing).
        let mut v = serde_json::Value::Array(vec![]);
        for _ in 0..MAX_PARSE_DEPTH {
            v = serde_json::Value::Array(vec![v]);
        }
        assert_eq!(
            canonicalize_json_value(&v).unwrap_err(),
            canon_fail()
        );
    }

    #[test]
    fn parse_depth_pathological_input_fails_clean() {
        // Without the depth bound this would recurse 100_000 deep and abort the
        // process (SIGABRT) via stack overflow. With the bound it must return a
        // clean CanonicalizationFailed long before exhausting the stack.
        let n = 100_000;
        let s = "[".repeat(n) + &"]".repeat(n);
        assert_eq!(
            canonicalize(s.as_bytes()).unwrap_err(),
            canon_fail()
        );
    }

    // ---- Serializer recursion bound on the PUBLIC JcsValue surface (MCPS-092) ----
    //
    // `JcsValue`'s container variants are public and re-exported at the crate
    // root, so an external caller can hand-construct a value tree FAR deeper than
    // any parse path can produce (parse is already capped at MAX_PARSE_DEPTH).
    // The serializer `write_value` must enforce the same bound and fail closed,
    // not overflow the stack. These tests drive that bound directly via the
    // public `canonicalize_value`.

    /// Build a value tree of exactly `n` nested `JcsValue::Array` containers
    /// around a `Number(0.0)` leaf, BOTTOM-UP and iteratively (heap, no stack
    /// recursion) so neither construction nor this test overflows. The outermost
    /// array is the one handed to `canonicalize_value` (serializer depth 0); the
    /// innermost is reached at serializer depth `n - 1`, matching the parser's
    /// depth accounting where `n` brackets reach depth `n - 1`.
    fn nested_array(n: usize) -> JcsValue {
        let mut v = JcsValue::Number(0.0);
        for _ in 0..n {
            v = JcsValue::Array(vec![v]);
        }
        v
    }

    #[test]
    fn write_value_depth_limit_rejects_deep_public_jcs_value() {
        // A hand-built JcsValue far deeper than MAX_PARSE_DEPTH (128). WITHOUT
        // the serializer bound, `write_value` would recurse to this depth and
        // overflow the stack (SIGABRT, aborting the whole process). WITH the
        // bound, it returns CanonicalizationFailed after ~128 frames — long
        // before any real stack pressure — so the asserting test runs clean.
        //
        // Depth is 5_000 (≫ 128), not 100_000: `JcsValue`'s derived `Drop` is
        // itself recursive, so a 100_000-deep tree overflows the stack on test
        // TEARDOWN (observed: SIGABRT in Drop, not in write_value). 5_000 proves
        // the bound trips (it fires at 128) while dropping safely. The depth is
        // ~39× the bound, so the bound is the only thing preventing overflow.
        let deep = nested_array(5_000);
        assert_eq!(
            canonicalize_value(&deep).unwrap_err(),
            canon_fail()
        );
    }

    #[test]
    fn write_value_depth_limit_rejects_just_over_max() {
        // MAX_PARSE_DEPTH + 1 nested arrays: the smallest tree that must be
        // rejected. Pairs with the exactly-max test below to prove the bound
        // trips on depth, at exactly the parse-path boundary.
        let just_over = nested_array(MAX_PARSE_DEPTH + 1);
        assert_eq!(
            canonicalize_value(&just_over).unwrap_err(),
            canon_fail()
        );
    }

    #[test]
    fn write_value_depth_limit_allows_exactly_max() {
        // MAX_PARSE_DEPTH nested arrays is the inclusive boundary and must
        // serialize, matching the parse path's exactly-max acceptance. This
        // proves the rejection above is due to depth, not a blanket failure.
        let at_max = nested_array(MAX_PARSE_DEPTH);
        canonicalize_value(&at_max)
            .expect("serializer depth at the inclusive boundary must canonicalize");
    }

    #[test]
    fn write_value_rejects_hand_built_object_with_duplicate_keys() {
        // The PUBLIC `JcsValue` surface is hand-constructible, so a caller can
        // build an Object that violates the JCS no-duplicate-key invariant that
        // `parse()`/`from_serde_value` would otherwise guarantee. The serializer
        // must re-enforce it (MCPS-092), mirroring the depth-bound treatment,
        // rather than emitting the duplicated key twice.
        let dup = JcsValue::Object(vec![
            ("a".to_string(), JcsValue::Number(1.0)),
            ("a".to_string(), JcsValue::Number(2.0)),
        ]);
        assert_eq!(
            canonicalize_value(&dup).unwrap_err(),
            canon_fail()
        );
    }

    #[test]
    fn write_value_accepts_hand_built_object_with_distinct_keys() {
        // Pairs with the duplicate-key rejection above: an Object with distinct
        // keys must still canonicalize, proving the rejection is keyed on
        // duplication, not a blanket Object failure.
        let ok = JcsValue::Object(vec![
            ("a".to_string(), JcsValue::Number(1.0)),
            ("b".to_string(), JcsValue::Number(2.0)),
        ]);
        canonicalize_value(&ok).expect("distinct-keyed object must canonicalize");
    }
}
