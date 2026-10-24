//! Upstream `initialize` gate (T-12b2, contracts/README.md N12).
//!
//! The one place the relay buffers a response: the upstream answer to a
//! downstream `initialize` is held, bounded, until the first complete JSON-RPC
//! response whose id equals the initialize id. The gate then judges the
//! negotiated revision and the capabilities the proxy cannot carry
//! (`capabilities.tasks`, `capabilities.resources.subscribe`).
//!
//! - The held bytes are never rewritten. On [`InitVerdict::Supported`] the
//!   caller relays [`InitGate::take_held`] (every received byte up to and
//!   including the one that completed the response, in order, SSE events
//!   before it included), then the remainder of the deciding chunk from
//!   [`InitGate::last_consumed`] on, then streams the rest. The held prefix
//!   never exceeds the total bound, whatever follows it in the same chunk.
//! - Only the security-relevant paths are read, each with duplicate keys
//!   refused: the envelope (`jsonrpc`, `id`, `method`, `result`, `error`),
//!   `result.protocolVersion`, `result.capabilities`, `capabilities.tasks`,
//!   `capabilities.resources` and `resources.subscribe`. Unknown fields are
//!   skipped, never reconstructed.
//! - Anything the gate cannot read within its bounds is
//!   [`InitVerdict::Unreadable`] (fail closed). Timeouts, network errors and
//!   the upstream session cleanup belong to the caller.
//!
//! Nothing held, no id and no field value is logged or shown by `Debug`.

use std::fmt;

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

use super::classify::RequestId;
use super::scan::{SseEv, SseParser};
use crate::body::{BodyMode, SseEventTracker};

/// The only revision a downstream session can be established on.
const SUPPORTED_VERSION: &str = "2025-11-25";

/// The gate's decision on the upstream `initialize` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitVerdict {
    /// Revision 2025-11-25, no unsupported capability: relay the held bytes.
    Supported,
    /// A well-formed answer with any other `protocolVersion` string
    /// (`upstream_version_unsupported`).
    VersionUnsupported,
    /// `capabilities.tasks` present (any value, `null` included) or
    /// `capabilities.resources.subscribe` is `true`
    /// (`upstream_capability_unsupported`).
    CapabilityUnsupported,
    /// The matching response is a JSON-RPC error.
    UpstreamError,
    /// Not decidable within the bounds: malformed, duplicate keys, wrong
    /// types, an opaque (encoded) body, a bound exceeded or end of stream
    /// before a matching response (`upstream_initialize_unreadable`).
    Unreadable,
}

pub struct InitGate {
    mode: BodyMode,
    id: RequestId,
    max_total: usize,
    max_event: usize,
    held: BytesMut,
    /// Bytes of the most recent `feed` chunk the gate consumed.
    consumed: usize,
    verdict: Option<InitVerdict>,
    json: JsonEnd,
    sse: SseParser,
    event: SseEventTracker,
    /// `data` of the current SSE event; at most `max_event` bytes.
    data: Vec<u8>,
}

impl fmt::Debug for InitGate {
    // Held bytes and the id are untrusted content: never shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitGate")
            .field("mode", &self.mode)
            .field("verdict", &self.verdict)
            .finish_non_exhaustive()
    }
}

impl InitGate {
    /// `max_total` bounds every byte held (the JSON response limit);
    /// `max_event` bounds one SSE event (the SSE event limit).
    pub fn new(mode: BodyMode, id: RequestId, max_total: usize, max_event: usize) -> InitGate {
        InitGate {
            mode,
            id,
            max_total,
            max_event,
            held: BytesMut::new(),
            consumed: 0,
            // An encoded body cannot be read without decoding it, which the
            // proxy never does.
            verdict: (mode == BodyMode::Opaque).then_some(InitVerdict::Unreadable),
            json: JsonEnd::default(),
            sse: SseParser::default(),
            event: SseEventTracker::default(),
            data: Vec::new(),
        }
    }

    /// Hold `chunk` and look for the matching response. `Some` once decided;
    /// later calls return the same verdict, consume and hold nothing more
    /// (the caller streams from there).
    ///
    /// Only the prefix of the deciding chunk up to and including the byte
    /// that completed the response is held, so the held bytes stay within
    /// `max_total`. The caller relays `chunk[self.last_consumed()..]` after
    /// [`InitGate::take_held`] on a relayable verdict.
    pub fn feed(&mut self, chunk: &[u8]) -> Option<InitVerdict> {
        self.consumed = 0;
        if self.verdict.is_some() {
            return self.verdict;
        }
        let mut used = 0;
        for &b in chunk {
            used += 1;
            if self.held.len() + used > self.max_total {
                self.consumed = used;
                return self.decide(InitVerdict::Unreadable);
            }
            let v = match self.mode {
                BodyMode::Json => self.json_byte(chunk, used, b),
                BodyMode::Sse => self.sse_byte(b),
                BodyMode::Opaque => Some(InitVerdict::Unreadable),
            };
            if let Some(v) = v {
                self.consumed = used;
                if v != InitVerdict::Unreadable {
                    self.held.extend_from_slice(&chunk[..used]);
                }
                return self.decide(v);
            }
        }
        self.consumed = chunk.len();
        self.held.extend_from_slice(chunk);
        None
    }

    /// Bytes of the most recent [`InitGate::feed`] chunk the gate consumed:
    /// the whole chunk while undecided, the prefix through the deciding byte
    /// on the call that decided, `0` on every call after a decision (and
    /// before any feed). `chunk[last_consumed()..]` is the caller's to relay
    /// on a relayable verdict; it was never held.
    pub fn last_consumed(&self) -> usize {
        self.consumed
    }

    /// End of the upstream body. Undecided means no complete matching
    /// response arrived: `Unreadable`.
    pub fn finish(&mut self) -> InitVerdict {
        match self.verdict {
            Some(v) => v,
            None => self
                .decide(InitVerdict::Unreadable)
                .unwrap_or(InitVerdict::Unreadable),
        }
    }

    /// Every byte consumed up to the decision, unchanged: at most `max_total`
    /// and never the deciding chunk's remainder. Empty after an
    /// `Unreadable` verdict (nothing of it may be relayed) and after a
    /// previous call.
    pub fn take_held(&mut self) -> Bytes {
        std::mem::take(&mut self.held).freeze()
    }

    fn decide(&mut self, v: InitVerdict) -> Option<InitVerdict> {
        self.verdict = Some(v);
        self.data = Vec::new();
        if v == InitVerdict::Unreadable {
            self.held = BytesMut::new();
        }
        Some(v)
    }

    /// `used` bytes of `chunk` are consumed, `b` being the last.
    fn json_byte(&mut self, chunk: &[u8], used: usize, b: u8) -> Option<InitVerdict> {
        match self.json.byte(b) {
            JsonStep::More => None,
            JsonStep::NotObject => Some(InitVerdict::Unreadable),
            JsonStep::End => {
                let mut msg = Vec::with_capacity(self.held.len() + used);
                msg.extend_from_slice(&self.held);
                msg.extend_from_slice(&chunk[..used]);
                // A plain response carries exactly one message: one that does
                // not match the initialize id cannot be answered later.
                Some(match judge(&msg, &self.id) {
                    Judged::Verdict(v) => v,
                    Judged::Skip => InitVerdict::Unreadable,
                })
            }
        }
    }

    fn sse_byte(&mut self, b: u8) -> Option<InitVerdict> {
        if self.event.feed(&[b], self.max_event as u64).is_err() {
            return Some(InitVerdict::Unreadable);
        }
        let data = &mut self.data;
        let id = &self.id;
        let max_event = self.max_event;
        let mut out = None;
        self.sse.feed(&[b], |ev| match ev {
            SseEv::Data(b) => push_data(data, b, max_event, &mut out),
            SseEv::DataBreak => push_data(data, b'\n', max_event, &mut out),
            SseEv::EventEnd => {
                if !data
                    .iter()
                    .all(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    if let Judged::Verdict(v) = judge(data, id) {
                        out = Some(v);
                    }
                }
                // priming / notification / server request / other id: next
                data.clear();
            }
        });
        out
    }
}

fn push_data(data: &mut Vec<u8>, b: u8, max: usize, out: &mut Option<InitVerdict>) {
    // The event tracker already bounds the event; this keeps the buffer bound
    // independent of it.
    if data.len() >= max {
        *out = Some(InitVerdict::Unreadable);
    } else {
        data.push(b);
    }
}

// ------------------------------------------------------------ JSON framing

/// Finds the end of one top-level JSON object in a byte stream without
/// keeping it: string/escape state and nesting depth only. Validity is left
/// to the parse at the end.
#[derive(Default)]
struct JsonEnd {
    depth: usize,
    started: bool,
    in_str: bool,
    esc: bool,
}

enum JsonStep {
    More,
    NotObject,
    End,
}

impl JsonEnd {
    fn byte(&mut self, b: u8) -> JsonStep {
        if !self.started {
            return match b {
                b' ' | b'\t' | b'\r' | b'\n' => JsonStep::More,
                b'{' => {
                    self.started = true;
                    self.depth = 1;
                    JsonStep::More
                }
                // a batch, a scalar or a byte-order mark
                _ => JsonStep::NotObject,
            };
        }
        if self.in_str {
            if self.esc {
                self.esc = false;
            } else if b == b'\\' {
                self.esc = true;
            } else if b == b'"' {
                self.in_str = false;
            }
            return JsonStep::More;
        }
        match b {
            b'"' => self.in_str = true,
            b'{' | b'[' => self.depth += 1,
            b'}' | b']' => {
                self.depth -= 1;
                if self.depth == 0 {
                    return JsonStep::End;
                }
            }
            _ => {}
        }
        JsonStep::More
    }
}

// --------------------------------------------------------------- judging

enum Judged {
    /// Not the initialize answer: a notification, a server request or a
    /// response to another id.
    Skip,
    Verdict(InitVerdict),
}

/// A field that is present with any JSON value, `null` included (a plain
/// `Option` would read `null` as absent). Serde's derived structs refuse a
/// repeated known field, so every field of this type rejects duplicates.
#[derive(Default)]
struct Field<'a>(Option<&'a RawValue>);

impl<'de: 'a, 'a> Deserialize<'de> for Field<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <&'a RawValue>::deserialize(d).map(|r| Field(Some(r)))
    }
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    jsonrpc: Field<'a>,
    #[serde(borrow, default)]
    id: Field<'a>,
    #[serde(borrow, default)]
    method: Field<'a>,
    #[serde(borrow, default)]
    result: Field<'a>,
    #[serde(borrow, default)]
    error: Field<'a>,
}

#[derive(Deserialize)]
struct InitResult<'a> {
    #[serde(rename = "protocolVersion", borrow, default)]
    protocol_version: Field<'a>,
    #[serde(borrow, default)]
    capabilities: Field<'a>,
}

#[derive(Deserialize)]
struct Capabilities<'a> {
    #[serde(borrow, default)]
    tasks: Field<'a>,
    #[serde(borrow, default)]
    resources: Field<'a>,
}

#[derive(Deserialize)]
struct Resources<'a> {
    #[serde(borrow, default)]
    subscribe: Field<'a>,
}

fn is_object(raw: &RawValue) -> bool {
    raw.get().trim_start().starts_with('{')
}

/// A derived struct also deserializes from a JSON array; only an object is
/// accepted here.
fn object<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> Option<T> {
    if !is_object(raw) {
        return None;
    }
    serde_json::from_str(raw.get()).ok()
}

/// Judge one complete message. Duplicate envelope keys or unparseable JSON
/// are `Unreadable` whatever the id: the id of such a message is not known.
fn judge(msg: &[u8], init_id: &RequestId) -> Judged {
    const UNREADABLE: Judged = Judged::Verdict(InitVerdict::Unreadable);
    let Ok(env) = serde_json::from_slice::<Envelope>(msg) else {
        return UNREADABLE;
    };
    if env.method.0.is_some() {
        return Judged::Skip; // notification or server-to-client request
    }
    let matches = env
        .id
        .0
        .and_then(|raw| RequestId::from_raw(raw.get()))
        .is_some_and(|id| id == *init_id);
    if !matches {
        return Judged::Skip;
    }
    // From here on this is the initialize answer.
    let jsonrpc_ok = env
        .jsonrpc
        .0
        .and_then(|raw| serde_json::from_str::<&str>(raw.get()).ok())
        .is_some_and(|v| v == "2.0");
    if !jsonrpc_ok {
        return UNREADABLE;
    }
    let result = match (env.result.0, env.error.0) {
        (None, Some(e)) if is_object(e) => return Judged::Verdict(InitVerdict::UpstreamError),
        (Some(r), None) => r,
        _ => return UNREADABLE, // both, neither, or a non-object error
    };
    Judged::Verdict(judge_result(result).unwrap_or(InitVerdict::Unreadable))
}

/// `None` is `Unreadable`. Every structural check runs before the version and
/// capability verdicts, so a malformed answer is never read as merely
/// unsupported.
fn judge_result(result: &RawValue) -> Option<InitVerdict> {
    let r: InitResult = object(result)?;
    // A string version; a borrowed `&str` would refuse escapes.
    let version: String = serde_json::from_str(r.protocol_version.0?.get()).ok()?;
    let caps: Capabilities = object(r.capabilities.0?)?;
    let subscribe = match caps.resources.0 {
        None => false,
        Some(raw) => {
            let res: Resources = object(raw)?;
            match res.subscribe.0 {
                None => false,
                Some(s) => serde_json::from_str::<bool>(s.get()).ok()?,
            }
        }
    };
    Some(if version != SUPPORTED_VERSION {
        InitVerdict::VersionUnsupported
    } else if caps.tasks.0.is_some() || subscribe {
        InitVerdict::CapabilityUnsupported
    } else {
        InitVerdict::Supported
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 1 << 20;

    fn id(raw: &str) -> RequestId {
        RequestId::from_raw(raw).unwrap()
    }

    fn ok_result(caps: &str) -> String {
        format!(
            r#"{{"protocolVersion":"2025-11-25","capabilities":{caps},"serverInfo":{{"name":"s","version":"1"}}}}"#
        )
    }

    fn response(id: &str, result: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
    }

    fn sse(data: &str) -> String {
        format!("event: message\ndata: {data}\n\n")
    }

    /// The verdict and what the client would get on `Supported`: the held
    /// bytes, then the deciding chunk's remainder and the chunks after it,
    /// streamed. Checks the held bound and the consumed count on the way.
    fn run(
        mode: BodyMode,
        init: &str,
        chunks: &[&[u8]],
        total: usize,
        event: usize,
    ) -> (InitVerdict, Bytes) {
        let mut g = InitGate::new(mode, id(init), total, event);
        let mut v = None;
        let mut rest = Vec::new();
        for c in chunks {
            if v.is_some() {
                rest.extend_from_slice(c);
            } else {
                v = g.feed(c);
                let n = g.last_consumed();
                if v.is_some() {
                    assert!(n <= c.len());
                    rest.extend_from_slice(&c[n..]);
                } else {
                    assert_eq!(n, c.len(), "undecided consumes the whole chunk");
                }
            }
        }
        let v = v.unwrap_or_else(|| g.finish());
        let held = g.take_held();
        assert!(held.len() <= total, "held within max_total");
        let mut out = held.to_vec();
        if v == InitVerdict::Supported {
            out.extend_from_slice(&rest);
        }
        (v, Bytes::from(out))
    }

    fn verdict(mode: BodyMode, init: &str, body: &str) -> InitVerdict {
        run(mode, init, &[body.as_bytes()], MAX, MAX).0
    }

    /// Whole, split at every position, and one byte at a time all agree.
    /// On `Supported` the held bytes equal the input exactly.
    fn verdict_all_splits(mode: BodyMode, init: &str, body: &str) -> InitVerdict {
        let b = body.as_bytes();
        let (whole, held) = run(mode, init, &[b], MAX, MAX);
        let check = |v: InitVerdict, held: &Bytes, how: &str| {
            assert_eq!(v, whole, "{how}");
            if v == InitVerdict::Supported {
                assert_eq!(&held[..], b, "{how}: bytes preserved in order");
            } else if v == InitVerdict::Unreadable {
                assert!(held.is_empty(), "{how}: nothing held");
            }
        };
        check(whole, &held, "whole");
        for i in 0..=b.len() {
            let (v, held) = run(mode, init, &[&b[..i], &b[i..]], MAX, MAX);
            check(v, &held, &format!("split at {i}"));
        }
        let ones: Vec<&[u8]> = b.chunks(1).collect();
        let (v, held) = run(mode, init, &ones, MAX, MAX);
        check(v, &held, "byte at a time");
        whole
    }

    use InitVerdict::*;
    const J: BodyMode = BodyMode::Json;
    const S: BodyMode = BodyMode::Sse;

    #[test]
    fn json_supported_preserves_bytes() {
        let body = response(
            "1",
            &ok_result(r#"{"tools":{"listChanged":true},"x-unknown":[1,{"a":"}"}]}"#),
        );
        assert_eq!(verdict_all_splits(J, "1", &body), Supported);
        // whitespace, unicode escapes and unknown fields are relayed untouched
        let body = "  {\"jsonrpc\":\"2.0\",\"id\":\"a\\u0062\",\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"z\":\"\\\"}\"}}\n";
        assert_eq!(verdict_all_splits(J, r#""ab""#, body), Supported);
    }

    #[test]
    fn json_error_response() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad"}}"#;
        assert_eq!(verdict_all_splits(J, "1", body), UpstreamError);
        // a non-object error, or both result and error, is unreadable
        let body = r#"{"jsonrpc":"2.0","id":1,"error":"bad"}"#;
        assert_eq!(verdict(J, "1", body), Unreadable);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{},"error":{{}}}}"#,
            ok_result("{}")
        );
        assert_eq!(verdict(J, "1", &body), Unreadable);
        let body = r#"{"jsonrpc":"2.0","id":1}"#;
        assert_eq!(verdict(J, "1", body), Unreadable);
    }

    #[test]
    fn json_envelope_checks() {
        let r = ok_result("{}");
        // missing or wrong jsonrpc
        assert_eq!(
            verdict(J, "1", &format!(r#"{{"id":1,"result":{r}}}"#)),
            Unreadable
        );
        assert_eq!(
            verdict(
                J,
                "1",
                &format!(r#"{{"jsonrpc":"1.0","id":1,"result":{r}}}"#)
            ),
            Unreadable
        );
        // a plain body holds one message: other id or a request is unreadable
        assert_eq!(verdict(J, "1", &response("2", &r)), Unreadable);
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        assert_eq!(verdict(J, "1", req), Unreadable);
        // batch / scalar / BOM / garbage
        for bad in ["[{}]", "\"x\"", "\u{feff}{}", "nope", "{", ""] {
            assert_eq!(verdict(J, "1", bad), Unreadable, "{bad:?}");
        }
    }

    #[test]
    fn string_and_number_ids_differ() {
        let r = ok_result("{}");
        assert_eq!(verdict(J, "1", &response(r#""1""#, &r)), Unreadable);
        assert_eq!(verdict(J, r#""1""#, &response("1", &r)), Unreadable);
        assert_eq!(verdict(J, "1", &response("1.0", &r)), Unreadable);
        assert_eq!(verdict(J, r#""1""#, &response(r#""1""#, &r)), Supported);
        // SSE: the number-id response is skipped, the string one decides
        let body = format!(
            "{}{}",
            sse(&response("1", &ok_result(r#"{"tasks":{}}"#))),
            sse(&response(r#""1""#, &r))
        );
        assert_eq!(verdict_all_splits(S, r#""1""#, &body), Supported);
    }

    #[test]
    fn version_checks() {
        let v = |ver: &str| {
            response(
                "1",
                &format!(r#"{{"protocolVersion":{ver},"capabilities":{{}}}}"#),
            )
        };
        assert_eq!(
            verdict_all_splits(J, "1", &v(r#""2025-06-18""#)),
            VersionUnsupported
        );
        assert_eq!(verdict(J, "1", &v(r#""2025-11-25 ""#)), VersionUnsupported);
        assert_eq!(verdict(J, "1", &v(r#""2025-11-25""#)), Supported);
        for bad in ["20251125", "null", "[]", "{}"] {
            assert_eq!(verdict(J, "1", &v(bad)), Unreadable, "{bad}");
        }
        let missing = response("1", r#"{"capabilities":{}}"#);
        assert_eq!(verdict(J, "1", &missing), Unreadable);
        // structure is checked before the version
        let both = response("1", r#"{"protocolVersion":"2025-06-18","capabilities":[]}"#);
        assert_eq!(verdict(J, "1", &both), Unreadable);
        // version is reported before capabilities
        let both = response(
            "1",
            r#"{"protocolVersion":"2025-06-18","capabilities":{"tasks":{}}}"#,
        );
        assert_eq!(verdict(J, "1", &both), VersionUnsupported);
    }

    #[test]
    fn capability_checks() {
        let c = |caps: &str| response("1", &ok_result(caps));
        assert_eq!(
            verdict_all_splits(J, "1", &c(r#"{"tasks":{}}"#)),
            CapabilityUnsupported
        );
        assert_eq!(
            verdict(J, "1", &c(r#"{"tasks":null}"#)),
            CapabilityUnsupported
        );
        assert_eq!(
            verdict(J, "1", &c(r#"{"tasks":false}"#)),
            CapabilityUnsupported
        );
        assert_eq!(
            verdict(J, "1", &c(r#"{"tasks":{}}"#)),
            CapabilityUnsupported
        );
        // `result.tasks` or a nested `tasks` is not the capability
        assert_eq!(verdict(J, "1", &c(r#"{"tools":{"tasks":{}}}"#)), Supported);
        assert_eq!(
            verdict_all_splits(J, "1", &c(r#"{"resources":{"subscribe":true}}"#)),
            CapabilityUnsupported
        );
        assert_eq!(
            verdict(
                J,
                "1",
                &c(r#"{"resources":{"subscribe":false,"listChanged":true}}"#)
            ),
            Supported
        );
        assert_eq!(verdict(J, "1", &c(r#"{"resources":{}}"#)), Supported);
        for bad in [
            r#"{"resources":{"subscribe":"true"}}"#,
            r#"{"resources":{"subscribe":null}}"#,
            r#"{"resources":{"subscribe":1}}"#,
            r#"{"resources":null}"#,
            r#"{"resources":true}"#,
            "null",
            "[]",
            "true",
        ] {
            assert_eq!(verdict(J, "1", &c(bad)), Unreadable, "{bad}");
        }
        let missing = response("1", r#"{"protocolVersion":"2025-11-25"}"#);
        assert_eq!(verdict(J, "1", &missing), Unreadable);
        assert_eq!(verdict(J, "1", &response("1", "[]")), Unreadable);
        let arr = response(
            "1",
            r#"{"protocolVersion":"2025-11-25","capabilities":{"resources":[]}}"#,
        );
        assert_eq!(verdict(J, "1", &arr), Unreadable);
        assert_eq!(verdict(J, "1", &response("1", "null")), Unreadable);
    }

    #[test]
    fn duplicate_keys_refused() {
        let r = ok_result("{}");
        let cases = [
            format!(r#"{{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"result":{r}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"id":1,"result":{r}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":2,"id":1,"result":{r}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":{r},"result":{r}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":{r},"error":{{}},"error":{{}}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"x","method":"y","result":{r}}}"#),
            response(
                "1",
                r#"{"protocolVersion":"2025-11-25","protocolVersion":"2025-06-18","capabilities":{}}"#,
            ),
            response(
                "1",
                r#"{"protocolVersion":"2025-11-25","capabilities":{},"capabilities":{}}"#,
            ),
            response("1", &ok_result(r#"{"tasks":{},"tasks":{}}"#)),
            response("1", &ok_result(r#"{"resources":{},"resources":{}}"#)),
            response(
                "1",
                &ok_result(r#"{"resources":{"subscribe":false,"subscribe":true}}"#),
            ),
            // an escaped spelling is the same key
            format!(r#"{{"jsonrpc":"2.0","id":1,"id":1,"result":{r}}}"#),
        ];
        for body in &cases {
            assert_eq!(verdict(J, "1", body), Unreadable, "{body}");
            assert_eq!(verdict(S, "1", &sse(body)), Unreadable, "sse {body}");
        }
        // unknown keys may repeat; they are skipped, not read
        let body = response("1", &ok_result(r#"{"tools":{},"tools":{}}"#));
        assert_eq!(verdict(J, "1", &body), Supported);
    }

    #[test]
    fn sse_supported_after_preceding_events() {
        let body = format!(
            "id: prime-0\ndata:\n\n: comment\n\n{}{}{}{}{}",
            sse(
                r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"x"}}"#
            ),
            sse(r#"{"jsonrpc":"2.0","id":1,"method":"roots/list"}"#),
            sse(&response("2", &ok_result(r#"{"tasks":{}}"#))),
            sse(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}"#),
            sse(&response("1", &ok_result(r#"{"tools":{}}"#))),
        );
        assert_eq!(verdict_all_splits(S, "1", &body), Supported);
    }

    #[test]
    fn sse_decides_on_first_match_and_holds_only_prefix() {
        let first = sse(&response("1", &ok_result("{}")));
        let rest = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\n\ndata: tail";
        let body = format!("{first}{rest}");
        let (v, out) = run(S, "1", &[body.as_bytes()], MAX, MAX);
        assert_eq!(v, Supported);
        assert_eq!(&out[..], body.as_bytes());
        let mut g = InitGate::new(S, id("1"), MAX, MAX);
        assert_eq!(g.feed(body.as_bytes()), Some(Supported));
        assert_eq!(g.last_consumed(), first.len());
        assert_eq!(&g.take_held()[..], first.as_bytes());
        // later feeds consume and hold nothing more and keep the verdict
        let mut g = InitGate::new(S, id("1"), MAX, MAX);
        assert_eq!(g.feed(first.as_bytes()), Some(Supported));
        assert_eq!(g.last_consumed(), first.len());
        assert_eq!(g.feed(b"data: more\n\n"), Some(Supported));
        assert_eq!(g.last_consumed(), 0);
        assert_eq!(g.finish(), Supported);
        assert_eq!(&g.take_held()[..], first.as_bytes());
        assert!(g.take_held().is_empty());
    }

    /// Feeds `head` then `prefix[split..] + tail` as the deciding chunk:
    /// the verdict comes with exactly `prefix` held, `max_total` set to its
    /// length, and held + remainder reconstructs the input.
    fn assert_tail_not_held(mode: BodyMode, prefix: &[u8], tail: &[u8], split: usize) {
        let total = prefix.len();
        let mut g = InitGate::new(mode, id("1"), total, MAX);
        assert_eq!(g.feed(&prefix[..split]), None, "split {split}");
        assert_eq!(g.last_consumed(), split);
        let mut chunk = prefix[split..].to_vec();
        chunk.extend_from_slice(tail);
        assert_eq!(g.feed(&chunk), Some(Supported), "split {split}");
        let n = g.last_consumed();
        assert_eq!(n, prefix.len() - split, "consumed up to the response end");
        // later feeds neither consume nor hold
        assert_eq!(g.feed(tail), Some(Supported));
        assert_eq!(g.last_consumed(), 0);
        let held = g.take_held();
        assert!(held.len() <= total);
        assert_eq!(&held[..], prefix);
        let mut out = held.to_vec();
        out.extend_from_slice(&chunk[n..]);
        let mut input = prefix.to_vec();
        input.extend_from_slice(tail);
        assert_eq!(out, input, "split {split}: held + remainder is the input");
    }

    #[test]
    fn large_tail_in_deciding_chunk_is_not_held() {
        let tail = vec![b'x'; 4 * MAX];
        // JSON: trailing bytes after the object are the caller's to stream
        let body = response("1", &ok_result("{}"));
        for split in [0, 1, body.len() / 2, body.len() - 1] {
            assert_tail_not_held(J, body.as_bytes(), &tail, split);
        }
        // SSE: events before the match are held, events after it are not
        let pre = format!(
            "id: prime-0\ndata:\n\n{}{}",
            sse(r#"{"jsonrpc":"2.0","method":"notifications/x"}"#),
            sse(&response("2", &ok_result("{}")))
        );
        let prefix = format!("{pre}{}", sse(&response("1", &ok_result("{}"))));
        let mut tail = sse(r#"{"jsonrpc":"2.0","method":"notifications/y"}"#).into_bytes();
        tail.extend_from_slice(&sse(&response("1", &ok_result(r#"{"tasks":{}}"#))).into_bytes());
        tail.extend(std::iter::repeat_n(b'x', 4 * MAX));
        for split in [0, 1, pre.len(), prefix.len() - 1] {
            assert_tail_not_held(S, prefix.as_bytes(), &tail, split);
        }
    }

    #[test]
    fn sse_refusals() {
        let body = sse(&response(
            "1",
            r#"{"protocolVersion":"2025-06-18","capabilities":{}}"#,
        ));
        assert_eq!(verdict_all_splits(S, "1", &body), VersionUnsupported);
        let body = sse(&response("1", &ok_result(r#"{"tasks":null}"#)));
        assert_eq!(verdict_all_splits(S, "1", &body), CapabilityUnsupported);
        let body = sse(&response(
            "1",
            &ok_result(r#"{"resources":{"subscribe":true}}"#),
        ));
        assert_eq!(verdict(S, "1", &body), CapabilityUnsupported);
        let body = sse(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"m"}}"#);
        assert_eq!(verdict_all_splits(S, "1", &body), UpstreamError);
        // unparseable event data is unreadable, not skipped
        assert_eq!(verdict(S, "1", "data: not json\n\n"), Unreadable);
    }

    #[test]
    fn sse_line_endings() {
        let msg = response("1", &ok_result("{}"));
        let (a, b) = msg.split_at(msg.find(",\"id\"").unwrap());
        for nl in ["\n", "\r\n", "\r"] {
            // a multi-line data field: lines join with "\n", valid JSON whitespace
            let body = format!(
                ": prime{nl}{nl}data: {{\"jsonrpc\":\"2.0\",\"method\":\"n\"}}{nl}{nl}event: message{nl}data: {a}{nl}data:{b}{nl}{nl}"
            );
            assert_eq!(verdict_all_splits(S, "1", &body), Supported, "{nl:?}");
        }
        // a CR immediately followed by an LF in the next chunk is one terminator
        let body = format!("data: {msg}\r\n\r\n");
        let mut g = InitGate::new(S, id("1"), MAX, MAX);
        assert_eq!(g.feed(&body.as_bytes()[..body.len() - 3]), None);
        assert_eq!(g.feed(b"\n"), None);
        assert_eq!(g.feed(b"\r"), Some(Supported));
        assert_eq!(&g.take_held()[..], &body.as_bytes()[..body.len() - 1]);
    }

    #[test]
    fn sse_incomplete_event_waits_then_eof_unreadable() {
        let msg = response("1", &ok_result("{}"));
        let mut g = InitGate::new(S, id("1"), MAX, MAX);
        assert_eq!(g.feed(format!("data: {msg}\n").as_bytes()), None);
        assert_eq!(g.finish(), Unreadable);
        assert!(g.take_held().is_empty());
    }

    #[test]
    fn json_incomplete_waits_then_eof_unreadable() {
        let msg = response("1", &ok_result("{}"));
        let mut g = InitGate::new(J, id("1"), MAX, MAX);
        assert_eq!(g.feed(&msg.as_bytes()[..msg.len() - 1]), None);
        assert_eq!(g.finish(), Unreadable);
        assert!(g.take_held().is_empty());
    }

    #[test]
    fn unmatched_eof_unreadable() {
        let body = format!(
            "{}{}",
            sse(&response("2", &ok_result("{}"))),
            sse(r#"{"jsonrpc":"2.0","method":"notifications/x"}"#)
        );
        assert_eq!(verdict_all_splits(S, "1", &body), Unreadable);
        assert_eq!(verdict(S, "1", ""), Unreadable);
        assert_eq!(verdict(J, "1", ""), Unreadable);
    }

    #[test]
    fn opaque_is_unreadable() {
        let body = response("1", &ok_result("{}"));
        let mut g = InitGate::new(BodyMode::Opaque, id("1"), MAX, MAX);
        assert_eq!(g.feed(body.as_bytes()), Some(Unreadable));
        assert_eq!(g.finish(), Unreadable);
        assert!(g.take_held().is_empty());
        let mut g = InitGate::new(BodyMode::Opaque, id("1"), MAX, MAX);
        assert_eq!(g.finish(), Unreadable);
    }

    #[test]
    fn total_bound() {
        let body = response("1", &ok_result("{}"));
        let n = body.len();
        assert_eq!(run(J, "1", &[body.as_bytes()], n, MAX).0, Supported);
        assert_eq!(
            run(J, "1", &[body.as_bytes()], n - 1, MAX),
            (Unreadable, Bytes::new())
        );
        let ones: Vec<&[u8]> = body.as_bytes().chunks(1).collect();
        assert_eq!(run(J, "1", &ones, n - 1, MAX), (Unreadable, Bytes::new()));
        // SSE: preceding events count toward the total
        let pre = sse(r#"{"jsonrpc":"2.0","method":"notifications/x"}"#);
        let body = format!("{pre}{}", sse(&body));
        let n = body.len();
        assert_eq!(run(S, "1", &[body.as_bytes()], n, MAX).0, Supported);
        assert_eq!(
            run(
                S,
                "1",
                &[pre.as_bytes(), &body.as_bytes()[pre.len()..]],
                n - 1,
                MAX
            )
            .0,
            Unreadable
        );
    }

    #[test]
    fn event_bound() {
        let event = sse(&response("1", &ok_result("{}")));
        let n = event.len();
        // the event's bytes include its closing blank line
        assert_eq!(run(S, "1", &[event.as_bytes()], MAX, n).0, Supported);
        assert_eq!(
            run(S, "1", &[event.as_bytes()], MAX, n - 1),
            (Unreadable, Bytes::new())
        );
        // an oversize preceding event is unreadable even if it would be skipped
        let big = sse(&format!(
            r#"{{"jsonrpc":"2.0","method":"n","params":{{"p":"{}"}}}}"#,
            "x".repeat(200)
        ));
        let body = format!("{big}{event}");
        assert_eq!(run(S, "1", &[body.as_bytes()], MAX, n).0, Unreadable);
        // but every event within the bound is fine however many there are
        let small = sse(r#"{"jsonrpc":"2.0","method":"n"}"#);
        let body = format!("{}{event}", small.repeat(100));
        assert_eq!(run(S, "1", &[body.as_bytes()], MAX, n).0, Supported);
    }

    #[test]
    fn debug_hides_content() {
        let mut g = InitGate::new(S, id(r#""secret-id""#), MAX, MAX);
        g.feed(b"data: {\"canary\":\"CANARY-123\"");
        let d = format!("{g:?}");
        assert!(!d.contains("secret") && !d.contains("CANARY"), "{d}");
    }
}
