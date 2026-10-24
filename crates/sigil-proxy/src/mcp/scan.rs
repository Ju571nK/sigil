//! Streaming scanners for upstream responses (T-12b1). They look at bytes that
//! are already on their way to the client and keep only a handful of facts:
//! constant memory per message, no copy of the result, no buffering.
//!
//! - [`MsgScanner`]: one JSON-RPC message. Recognises the top-level `id`,
//!   `method`, `result`, `error` keys and `result.isError`.
//! - [`SseParser`]: SSE line framing (`\n`, `\r\n`, `\r`) that hands the `data`
//!   field bytes of each event to a callback.
//!
//! Both are permissive: malformed input never panics, it only yields fewer
//! facts (which classifies as unknown, never as success).

use super::classify::{RequestId, MAX_ID_BYTES};

/// What the scanner learned about one message.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The value was a complete top-level object.
    pub complete: bool,
    pub has_method: bool,
    pub has_result: bool,
    pub has_error: bool,
    /// `result.isError` was literally `true`.
    pub is_error: bool,
    /// `result.task` was an object: a task handle (2025-11-25 `CreateTaskResult`).
    pub has_task: bool,
    pub id: IdFact,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum IdFact {
    #[default]
    Missing,
    Null,
    Value(RequestId),
    /// Present but not a short string/number.
    Invalid,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Key {
    None,
    Id,
    Method,
    Result,
    Error,
    IsError,
    Task,
    Other,
}

#[derive(Clone, Copy)]
struct Frame {
    obj: bool,
    expect_key: bool,
    key: Key,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StrRole {
    Skip,
    Key,
    Id,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LitRole {
    Skip,
    Id,
    IsError,
    Task,
}

const MAX_TRACKED: usize = 2;
const KEY_CAP: usize = 8;
// `"` + MAX_ID_BYTES + escapes headroom; an id above this is invalid anyway.
const ID_CAP: usize = MAX_ID_BYTES + 8;

pub struct MsgScanner {
    frames: [Frame; MAX_TRACKED],
    n: usize,
    deep: usize,
    started: bool,
    is_obj: bool,
    done: bool,
    facts: Facts,
    // string state
    in_str: bool,
    esc: bool,
    uni: u8,
    ucode: u32,
    role: StrRole,
    key: [u8; KEY_CAP],
    key_len: usize,
    key_other: bool,
    // id / literal capture
    id_buf: Vec<u8>,
    id_over: bool,
    lit: Vec<u8>,
    lit_role: LitRole,
    in_lit: bool,
}

const NO_FRAME: Frame = Frame {
    obj: false,
    expect_key: false,
    key: Key::None,
};

impl Default for MsgScanner {
    fn default() -> Self {
        MsgScanner {
            frames: [NO_FRAME; MAX_TRACKED],
            n: 0,
            deep: 0,
            started: false,
            is_obj: false,
            done: false,
            facts: Facts::default(),
            in_str: false,
            esc: false,
            uni: 0,
            ucode: 0,
            role: StrRole::Skip,
            key: [0; KEY_CAP],
            key_len: 0,
            key_other: false,
            id_buf: Vec::new(),
            id_over: false,
            lit: Vec::new(),
            lit_role: LitRole::Skip,
            in_lit: false,
        }
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_delim(b: u8) -> bool {
    is_ws(b) || matches!(b, b',' | b'}' | b']' | b':' | b'"' | b'{' | b'[')
}

impl MsgScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Finish the message and reset for the next one.
    pub fn take(&mut self) -> Facts {
        if self.in_lit {
            self.end_literal();
        }
        let mut facts = std::mem::take(&mut self.facts);
        facts.complete = self.done && self.is_obj;
        *self = MsgScanner::default();
        facts
    }

    pub fn feed(&mut self, data: &[u8]) {
        for &b in data {
            self.byte(b);
        }
    }

    fn top(&mut self) -> Option<&mut Frame> {
        if self.deep == 0 && self.n > 0 {
            Some(&mut self.frames[self.n - 1])
        } else {
            None
        }
    }

    fn byte(&mut self, b: u8) {
        if self.done {
            return;
        }
        if self.in_str {
            self.string_byte(b);
            return;
        }
        if self.in_lit {
            if is_delim(b) {
                self.end_literal();
            } else {
                if self.lit.len() < ID_CAP {
                    self.lit.push(b);
                }
                return;
            }
        }
        match b {
            _ if is_ws(b) => {}
            b'"' => self.begin_string(),
            b'{' | b'[' => self.open(b),
            b'}' | b']' => self.close(),
            b':' => {
                if let Some(f) = self.top() {
                    f.expect_key = false;
                }
            }
            b',' => {
                if let Some(f) = self.top() {
                    if f.obj {
                        f.expect_key = true;
                        f.key = Key::None;
                    }
                }
            }
            _ => self.begin_literal(b),
        }
    }

    /// A value starts in a tracked object slot. Returns the key it belongs to
    /// and the depth.
    fn value_slot(&mut self) -> Option<(Key, usize, Key)> {
        let n = self.n;
        let parent = if n >= 2 {
            self.frames[0].key
        } else {
            Key::None
        };
        let f = self.top()?;
        if !f.obj || f.expect_key {
            return None;
        }
        Some((f.key, n, parent))
    }

    fn note_value(&mut self) -> LitRole {
        let Some((key, depth, parent)) = self.value_slot() else {
            return LitRole::Skip;
        };
        match (depth, key) {
            (1, Key::Id) => LitRole::Id,
            (1, Key::Method) => {
                self.facts.has_method = true;
                LitRole::Skip
            }
            (1, Key::Result) => {
                self.facts.has_result = true;
                LitRole::Skip
            }
            (1, Key::Error) => {
                self.facts.has_error = true;
                LitRole::Skip
            }
            (2, Key::IsError) if parent == Key::Result => LitRole::IsError,
            (2, Key::Task) if parent == Key::Result => LitRole::Task,
            _ => LitRole::Skip,
        }
    }

    fn open(&mut self, b: u8) {
        if !self.started {
            self.started = true;
            if b != b'{' {
                self.done = true; // a batch or array: not a message
                return;
            }
            self.is_obj = true;
            self.frames[0] = Frame {
                obj: true,
                expect_key: true,
                key: Key::None,
            };
            self.n = 1;
            return;
        }
        if self.deep == 0 {
            match self.note_value() {
                LitRole::Id => self.facts.id = IdFact::Invalid, // a container is not an id
                LitRole::Task if b == b'{' => self.facts.has_task = true,
                _ => {}
            }
            if self.n < MAX_TRACKED {
                self.frames[self.n] = Frame {
                    obj: b == b'{',
                    expect_key: b == b'{',
                    key: Key::None,
                };
                self.n += 1;
                return;
            }
        }
        self.deep += 1;
    }

    fn close(&mut self) {
        if self.deep > 0 {
            self.deep -= 1;
        } else if self.n > 0 {
            self.n -= 1;
            if self.n == 0 {
                self.done = true;
            }
        }
    }

    fn begin_string(&mut self) {
        if !self.started {
            self.started = true;
            self.done = true;
            return;
        }
        self.in_str = true;
        self.esc = false;
        self.uni = 0;
        self.role = StrRole::Skip;
        if self.deep > 0 {
            return;
        }
        let is_key = self.top().is_some_and(|f| f.obj && f.expect_key);
        if is_key {
            self.role = StrRole::Key;
            self.key_len = 0;
            self.key_other = false;
        } else if self.note_value() == LitRole::Id {
            self.role = StrRole::Id;
            self.id_buf.clear();
            self.id_over = false;
            self.id_buf.push(b'"');
        }
    }

    fn string_byte(&mut self, b: u8) {
        // Escape / terminator tracking is common to every role.
        if self.uni > 0 {
            self.uni -= 1;
            self.ucode = (self.ucode << 4) | (b as char).to_digit(16).unwrap_or(0);
            self.role_push_raw(b);
            if self.uni == 0 {
                let c = self.ucode;
                if self.role == StrRole::Key {
                    if c < 0x80 {
                        self.key_push(c as u8);
                    } else {
                        self.key_other = true;
                    }
                }
            }
            return;
        }
        if self.esc {
            self.esc = false;
            self.role_push_raw(b);
            if b == b'u' {
                self.uni = 4;
                self.ucode = 0;
            } else if self.role == StrRole::Key {
                let d = match b {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    b'b' => 8,
                    b'f' => 12,
                    other => other, // '"', '\\', '/'
                };
                self.key_push(d);
            }
            return;
        }
        if b == b'\\' {
            self.esc = true;
            self.role_push_raw(b);
            return;
        }
        if b == b'"' {
            self.end_string();
            return;
        }
        self.role_push_raw(b);
        if self.role == StrRole::Key {
            if b >= 0x80 {
                self.key_other = true;
            } else {
                self.key_push(b);
            }
        }
    }

    fn role_push_raw(&mut self, b: u8) {
        if self.role == StrRole::Id {
            if self.id_buf.len() < ID_CAP {
                self.id_buf.push(b);
            } else {
                self.id_over = true;
            }
        }
    }

    fn key_push(&mut self, b: u8) {
        if self.key_len < KEY_CAP {
            self.key[self.key_len] = b;
            self.key_len += 1;
        } else {
            self.key_other = true;
        }
    }

    fn end_string(&mut self) {
        self.in_str = false;
        match self.role {
            StrRole::Key => {
                let name: &[u8] = if self.key_other {
                    b""
                } else {
                    &self.key[..self.key_len]
                };
                let depth = self.n;
                let parent = if depth >= 2 {
                    self.frames[0].key
                } else {
                    Key::None
                };
                let k = match (depth, name) {
                    (1, b"id") => Key::Id,
                    (1, b"method") => Key::Method,
                    (1, b"result") => Key::Result,
                    (1, b"error") => Key::Error,
                    (2, b"isError") if parent == Key::Result => Key::IsError,
                    (2, b"task") if parent == Key::Result => Key::Task,
                    _ => Key::Other,
                };
                if let Some(f) = self.top() {
                    f.key = k;
                }
            }
            StrRole::Id => {
                self.id_buf.push(b'"');
                self.facts.id = if self.id_over {
                    IdFact::Invalid
                } else {
                    std::str::from_utf8(&self.id_buf)
                        .ok()
                        .and_then(RequestId::from_raw)
                        .map(IdFact::Value)
                        .unwrap_or(IdFact::Invalid)
                };
            }
            StrRole::Skip => {}
        }
        self.role = StrRole::Skip;
    }

    fn begin_literal(&mut self, b: u8) {
        if !self.started {
            self.started = true;
            self.done = true;
            return;
        }
        self.lit_role = if self.deep == 0 {
            self.note_value()
        } else {
            LitRole::Skip
        };
        self.in_lit = true;
        self.lit.clear();
        self.lit.push(b);
    }

    fn end_literal(&mut self) {
        self.in_lit = false;
        match self.lit_role {
            LitRole::Id => {
                let s = std::str::from_utf8(&self.lit).unwrap_or("");
                self.facts.id = if s == "null" {
                    IdFact::Null
                } else {
                    RequestId::from_raw(s)
                        .map(IdFact::Value)
                        .unwrap_or(IdFact::Invalid)
                };
            }
            LitRole::IsError => {
                if self.lit == b"true" {
                    self.facts.is_error = true;
                }
            }
            LitRole::Task | LitRole::Skip => {}
        }
        self.lit_role = LitRole::Skip;
    }
}

// -------------------------------------------------------------------- SSE

/// What the SSE framer reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseEv {
    /// One byte of a `data` field value.
    Data(u8),
    /// A line break between two `data` lines of one event (a `\n` in the data).
    DataBreak,
    /// A blank line ended an event that had at least one `data` field.
    EventEnd,
}

#[derive(Clone, Copy)]
enum Line {
    Name { buf: [u8; 4], len: usize },
    Data { skip_space: bool },
    Ignore,
}

const BLANK: Line = Line::Name {
    buf: [0; 4],
    len: 0,
};

/// SSE line framing per the WHATWG rules the relay already uses for event
/// sizing (`body::SseEventTracker`): terminators are `\n`, `\r\n` or `\r`. An
/// event still open at end of stream is discarded, as a client would.
pub struct SseParser {
    line: Line,
    after_cr: bool,
    had_data: bool,
}

impl Default for SseParser {
    fn default() -> Self {
        SseParser {
            line: BLANK,
            after_cr: false,
            had_data: false,
        }
    }
}

impl SseParser {
    pub fn feed(&mut self, data: &[u8], mut out: impl FnMut(SseEv)) {
        for &b in data {
            self.byte(b, &mut out);
        }
    }

    fn byte(&mut self, b: u8, out: &mut impl FnMut(SseEv)) {
        if self.after_cr {
            self.after_cr = false;
            if b == b'\n' {
                return;
            }
        }
        if b == b'\r' || b == b'\n' {
            self.after_cr = b == b'\r';
            self.end_line(out);
            return;
        }
        match &mut self.line {
            Line::Name { buf, len } => {
                if b == b':' {
                    if &buf[..*len] == b"data" && *len == 4 {
                        self.start_data(out);
                    } else {
                        self.line = Line::Ignore;
                    }
                } else if *len < buf.len() {
                    buf[*len] = b;
                    *len += 1;
                } else {
                    // longer than any field name this parser cares about
                    // ("data" has 4); `dataX` etc. are other fields.
                    self.line = Line::Ignore;
                }
            }
            Line::Data { skip_space } => {
                if *skip_space && b == b' ' {
                    *skip_space = false;
                } else {
                    *skip_space = false;
                    out(SseEv::Data(b));
                }
            }
            Line::Ignore => {}
        }
    }

    fn start_data(&mut self, out: &mut impl FnMut(SseEv)) {
        if self.had_data {
            out(SseEv::DataBreak);
        }
        self.had_data = true;
        self.line = Line::Data { skip_space: true };
    }

    fn end_line(&mut self, out: &mut impl FnMut(SseEv)) {
        match self.line {
            Line::Name { buf, len } => {
                if len == 0 {
                    if self.had_data {
                        out(SseEv::EventEnd);
                    }
                    self.had_data = false;
                } else if &buf[..len] == b"data" {
                    // `data` with no colon: a data field with an empty value
                    self.start_data(out);
                }
            }
            Line::Data { .. } | Line::Ignore => {}
        }
        self.line = BLANK;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(chunks: &[&[u8]]) -> Facts {
        let mut s = MsgScanner::new();
        for c in chunks {
            s.feed(c);
        }
        s.take()
    }

    /// Feed the message split at every byte position; all splits agree.
    fn scan_all_splits(msg: &[u8]) -> Facts {
        let whole = scan(&[msg]);
        for i in 0..=msg.len() {
            assert_eq!(scan(&[&msg[..i], &msg[i..]]), whole, "split at {i}");
        }
        // and one byte at a time
        let ones: Vec<&[u8]> = msg.chunks(1).collect();
        assert_eq!(scan(&ones), whole);
        whole
    }

    fn id(s: &str) -> IdFact {
        IdFact::Value(RequestId::from_raw(s).unwrap())
    }

    #[test]
    fn success_response() {
        let f = scan_all_splits(
            br#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"x"}],"isError":false}}"#,
        );
        assert!(f.complete && f.has_result && !f.has_error && !f.has_method && !f.is_error);
        assert_eq!(f.id, id("7"));
    }

    #[test]
    fn tool_error_is_result_with_is_error_true() {
        let f = scan_all_splits(
            br#"{"jsonrpc":"2.0","id":"a","result":{"isError":true,"content":[]}}"#,
        );
        assert!(f.has_result && f.is_error);
        assert_eq!(f.id, id("\"a\""));
        // isError last, after a nested array/object with its own isError
        let f = scan_all_splits(
            br#"{"result":{"content":[{"isError":true}],"structuredContent":{"isError":true},"isError":false},"id":1}"#,
        );
        assert!(!f.is_error, "only result.isError counts");
    }

    /// N10 ii: only an object at `result.task` is a task handle.
    #[test]
    fn task_handle_is_an_object_at_result_task() {
        let f = scan_all_splits(
            br#"{"jsonrpc":"2.0","id":5,"result":{"task":{"taskId":"t","status":"working"}}}"#,
        );
        assert!(f.complete && f.has_result && f.has_task);
        for not in [
            &br#"{"id":5,"result":{"content":[{"task":{}}],"structuredContent":{"task":{}}}}"#[..],
            br#"{"id":5,"result":{"task":"x"}}"#,
            br#"{"id":5,"result":{"task":null}}"#,
            br#"{"id":5,"task":{},"result":{}}"#,
            br#"{"id":5,"error":{"task":{}}}"#,
        ] {
            assert!(
                !scan_all_splits(not).has_task,
                "{}",
                String::from_utf8_lossy(not)
            );
        }
    }

    #[test]
    fn json_rpc_error_response() {
        let f = scan_all_splits(
            br#"{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"bad","data":{"result":1,"isError":true}}}"#,
        );
        assert!(f.has_error && !f.has_result && !f.is_error);
        assert_eq!(f.id, id("3"));
    }

    #[test]
    fn server_requests_and_notifications_have_a_method() {
        let f = scan_all_splits(
            br#"{"jsonrpc":"2.0","id":"s","method":"sampling/createMessage","params":{"result":1}}"#,
        );
        assert!(f.has_method && !f.has_result);
        let f =
            scan_all_splits(br#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#);
        assert!(f.has_method);
        assert_eq!(f.id, IdFact::Missing);
    }

    #[test]
    fn keys_are_matched_after_unescaping_only_at_the_right_depth() {
        // an escaped key still matches; a nested "id" does not
        let f = scan_all_splits(
            br#"{"\u0069d":9,"res\u0075lt":{"\u0069sError":true},"x":{"id":99,"error":1}}"#,
        );
        assert_eq!(f.id, id("9"));
        assert!(f.has_result && f.is_error && !f.has_error);
        // a string value equal to a key name is not a key
        let f = scan_all_splits(br#"{"x":"id","y":["result","error"],"id":1}"#);
        assert!(!f.has_result && !f.has_error);
        assert_eq!(f.id, id("1"));
    }

    #[test]
    fn id_shapes() {
        for (msg, want) in [
            (&br#"{"id":"abc","result":1}"#[..], id("\"abc\"")),
            (
                br#"{"id":12345678901234567890123456789,"result":1}"#,
                id("12345678901234567890123456789"),
            ),
            (br#"{"id":-1.5e3,"result":1}"#, id("-1.5e3")),
            (br#"{"id":"a\u00e9\n","result":1}"#, id(r#""a\u00e9\n""#)),
            (br#"{"id":null,"error":{}}"#, IdFact::Null),
            (br#"{"id":true,"result":1}"#, IdFact::Invalid),
            (br#"{"id":{"a":1},"result":1}"#, IdFact::Invalid),
            (br#"{"id":[1],"result":1}"#, IdFact::Invalid),
            (br#"{"result":1}"#, IdFact::Missing),
        ] {
            assert_eq!(
                scan_all_splits(msg).id,
                want,
                "{}",
                String::from_utf8_lossy(msg)
            );
        }
        // an oversized id is invalid, not truncated
        let long = format!(r#"{{"id":"{}","result":1}}"#, "x".repeat(MAX_ID_BYTES + 50));
        assert_eq!(scan(&[long.as_bytes()]).id, IdFact::Invalid);
    }

    #[test]
    fn non_objects_and_truncation_are_not_complete() {
        assert!(!scan(&[b"[1,2]"]).complete);
        assert!(!scan(&[b"\"x\""]).complete);
        assert!(!scan(&[b"12"]).complete);
        assert!(!scan(&[b""]).complete);
        assert!(!scan(&[br#"{"id":1,"result":{"a":"#]).complete);
        // junk never panics
        for junk in [
            &b"}}}}"[..],
            b"{\"a\":\"\\",
            b"{{{{",
            b"\xff\xfe{",
            b"{\"id\":\"\\u12",
        ] {
            let _ = scan(&[junk]);
        }
    }

    #[test]
    fn deep_nesting_inside_params_is_handled_without_state() {
        let nest = "[".repeat(10_000) + &"]".repeat(10_000);
        let msg = format!(r#"{{"id":5,"result":{{"a":{nest},"isError":true}}}}"#);
        let f = scan(&[msg.as_bytes()]);
        assert!(f.complete && f.is_error);
        assert_eq!(f.id, id("5"));
    }

    #[test]
    fn take_resets_for_the_next_message() {
        let mut s = MsgScanner::new();
        s.feed(br#"{"id":1,"result":{}}"#);
        assert!(s.take().has_result);
        s.feed(br#"{"id":2,"error":{}}"#);
        let f = s.take();
        assert!(f.has_error && !f.has_result);
        assert_eq!(f.id, id("2"));
    }

    fn sse(chunks: &[&[u8]]) -> Vec<String> {
        let mut p = SseParser::default();
        let mut cur = Vec::<u8>::new();
        let mut events = Vec::new();
        for c in chunks {
            p.feed(c, |e| match e {
                SseEv::Data(b) => cur.push(b),
                SseEv::DataBreak => cur.push(b'\n'),
                SseEv::EventEnd => {
                    events.push(String::from_utf8(std::mem::take(&mut cur)).unwrap())
                }
            });
        }
        events
    }

    #[test]
    fn sse_framing() {
        let stream = b"id: 1\nevent: message\ndata: {\"a\":1}\n\n: comment\n\ndata:x\r\ndata: y\r\n\r\ndata\n\ndata: z\r\r\nretry: 5\n\n";
        let want = vec!["{\"a\":1}", "x\ny", "", "z"];
        assert_eq!(sse(&[stream]), want);
        for i in 0..=stream.len() {
            assert_eq!(sse(&[&stream[..i], &stream[i..]]), want, "split at {i}");
        }
        // `dataX:` and `data2` are other fields
        assert!(sse(&[b"data2: no\n\nxdata: no\n\n"]).is_empty());
        // an unterminated event is discarded
        assert!(sse(&[b"data: partial"]).is_empty());
        assert!(sse(&[b"data: partial\n"]).is_empty());
        // a field line with only a data prefix and no colon but trailing junk
        assert!(sse(&[b"datafoo\n\n"]).is_empty());
    }
}
