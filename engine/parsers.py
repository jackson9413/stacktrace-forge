"""Stack-trace and log parsing for stacktrace-forge.

Supports Java, Python, JavaScript/Node, C#, Go, Rust, Ruby and PHP traces,
plus a generic fallback. Also parses structured log lines so a pasted log
excerpt can be mined for observability signals.

Pure standard library: no network calls, no LLM.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    index: int = 0
    function: str = ""
    file: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    raw: str = ""
    origin: str = "unknown"
    in_app: bool = False

    @property
    def location(self) -> str:
        if self.file and self.line:
            return "%s:%s" % (self.file.rsplit("/", 1)[-1], self.line)
        if self.file:
            return self.file.rsplit("/", 1)[-1]
        return self.function or "unknown"

    @property
    def project(self) -> str:
        return self.file or ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "function": self.function,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "location": self.location,
            "origin": self.origin,
            "in_app": self.in_app,
            "raw": self.raw,
        }


@dataclass
class ParsedError:
    language: str = "unknown"
    error_type: str = ""
    message: str = ""
    frames: List[Frame] = field(default_factory=list)
    raw: str = ""
    timestamp: Optional[str] = None
    level: Optional[str] = None
    logger: Optional[str] = None
    thread: Optional[str] = None
    chain_index: int = 0
    chain_marker: str = ""

    @property
    def headline(self) -> str:
        if self.error_type and self.message:
            return "%s: %s" % (self.error_type, self.message)
        return self.error_type or self.message or self.raw.splitlines()[0][:200]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "error_type": self.error_type,
            "message": self.message,
            "headline": self.headline,
            "frames": [f.to_dict() for f in self.frames],
            "timestamp": self.timestamp,
            "level": self.level,
            "logger": self.logger,
            "thread": self.thread,
            "chain_index": self.chain_index,
            "chain_marker": self.chain_marker,
        }


@dataclass
class LogEntry:
    timestamp: Optional[str] = None
    level: Optional[str] = None
    logger: Optional[str] = None
    thread: Optional[str] = None
    message: str = ""
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "logger": self.logger,
            "thread": self.thread,
            "message": self.message,
            "raw": self.raw,
        }


# ---------------------------------------------------------------------------
# origin classification
# ---------------------------------------------------------------------------

_FRAMEWORK_RE = re.compile(
    r"(org\.springframework|org\.hibernate|com\.fasterxml|io\.netty|org\.apache\.(?:catalina|struts)|"
    r"\bdjango\b|\bflask\b|\bfastapi\b|\bstarlette\b|\bcelery\b|\bsqlalchemy\b|\btortoise\b|"
    r"\bexpress\b|\bkoa\b|\bnestjs\b|\breact-dom\b|\bnext/|\b@angular|\bvue/|\bwebpack\b|"
    r"\brails\b|\blaravel\b|\bsymfony\b|\bgorm\b|\bstripe\b|\btwilio\b|\bsendgrid\b)",
    re.I,
)
_LIBRARY_RE = re.compile(
    r"(site-packages|node_modules|/vendor/|/dist-packages|/usr/lib/python|/usr/local/lib/python|"
    r"/lib/ruby|/gems/|\.m2/repository|/go/pkg/mod|/Godeps/|/bundle/|/jars/|/gradle/caches|"
    r"/\.cargo/registry|[A-Z]:[\\/]{1,2}.*[\\/]{1,2}(node_modules|lib)[\\/]{1,2})",
    re.I,
)
_STDLIB_RE = re.compile(
    r"(^|[/\\])java\.lang\.|^java\.util\.|jdk\.internal|^sun\.|^javax\.|org\.junit|org\.testng|"
    r"^kotlin\.|^scala\.|^groovy\.|/python3?(\.\d+)?/(json|os|sys|re|logging|typing|asyncio|itertools|"
    r"functools|collections|dataclasses|unittest|inspect|traceback)\.py|^builtins\.py|"
    r"^ruby/|^/usr/lib/ruby|^_?(core|internal)/",
    re.I,
)
_APP_RE = re.compile(
    r"(/src/|/app/|/lib/|/packages/|/components/|/services/|/domain/|/handlers/|/cmd/|/internal/|"
    r"/pkg/|/web/|/api/|/features/|/routes/|/models?/)",
    re.I,
)
_TEST_RE = re.compile(
    r"(^|[/\\])(tests?|spec|__tests__)([/\\]|$)|_test\.|\.test\.|\.spec\.|Test\.java$",
    re.I,
)


def classify_origin(function: str, file: str) -> str:
    """Classify a frame as app / test / library / framework / stdlib / unknown."""
    probe = "%s %s" % (function or "", file or "")
    if _TEST_RE.search(probe):
        return "test"
    if _FRAMEWORK_RE.search(probe):
        return "framework"
    if _STDLIB_RE.search(probe):
        return "stdlib"
    if _LIBRARY_RE.search(probe):
        return "library"
    if _APP_RE.search(probe):
        return "app"
    # A fully qualified class or method path (com.acme.OrderService.run) is
    # application code unless a framework or library rule already claimed it.
    if re.match(r"^[a-z][\w]*(\.[a-z][\w]*)*\.[A-Z]", function or ""):
        return "app"
    if file and re.search(r"[A-Za-z]:\\|/home/|/Users/", file):
        return "app"
    return "unknown"


# ---------------------------------------------------------------------------
# language detection
# ---------------------------------------------------------------------------

_LANG_MARKERS = [
    ("java", [r"^\s*at [\w$.]+\([\w$]+\.java:\d+\)", r"Caused by:",
              r"^\s*at [\w$.]+\(Unknown Source\)", r'Exception in thread "',
              r"^(?:java|javax|com|org|net|io|sun|jdk)\.[\w.]*\.[A-Z][\w$]*"
              r"(?:Exception|Error|Throwable)\b"]),
    ("python", [r"Traceback \(most recent call last\)", r"During handling of the above exception",
                r'^\s+File "[^"]+", line \d+',
                r"^(?!(?:java|javax|com|org|net|sun|jdk|io)\b)[a-z_][\w.]*\.[A-Za-z_]\w*"
                r"(?:Error|Exception|Warning)\b"]),
    ("javascript", [r"^\s*at [\w$.<> ]+\(.*\.(js|mjs|cjs|ts|tsx)(:\d+){1,2}\)",
                    r"^\s*at .*\.(js|mjs|cjs|ts|tsx):\d+:\d+", r"node:internal",
                    r"errno: -?\d+", r"UnhandledPromiseRejection", r"^\s*at .*:\d+:\d+"]),
    ("csharp", [r"^System\.\w+Exception:", r"^\s+at [\w.<>\[\]]+\(.*\) in .*\.cs:line \d+",
                r"Stack Trace:"]),
    ("go", [r"^goroutine \d+ \[", r"^panic: ", r"^\s*/[\w./-]+\.go:\d+"]),
    ("rust", [r"^thread '.*' panicked at ", r"^\s*/[\w./-]+\.rs:\d+:\d+"]),
    ("ruby", [r"\(NoMethodError\)", r"\(ArgumentError\)", r"^\s+from .*:\d+:in ", r"undefined method"]),
    ("php", [r"PHP (Fatal error|Parse error|Warning|Notice)", r"Uncaught \w+Error", r"\.php on line \d+"]),
]


def detect_language(text: str) -> str:
    """Return the best-guess language id for a trace block."""
    for lang, patterns in _LANG_MARKERS:
        for pat in patterns:
            if re.search(pat, text, re.M):
                return lang
    return "unknown"


# ---------------------------------------------------------------------------
# per-language parsers
# ---------------------------------------------------------------------------

_JAVA_HEADER_RE = re.compile(
    r"^(?:Caused by:\s*|Suppressed:\s*)?((?:[A-Za-z_$][\w$]*\.)*(?:[A-Z][\w$]*(?:Exception|Error|Throwable|Condition)))\b"
    r"(?::\s*(.*))?$"
)
_JAVA_FRAME_RE = re.compile(r"^\s*at\s+(.+?)\((.*)\)\s*$")
_PY_FRAME_RE = re.compile(r'^\s*File "([^"]+)", line (\d+)(?:, in (.+))?\s*$')
_JS_FRAME_RE = re.compile(r"^\s*at\s+(?:(.+?)\s+\()?(.+?)(?::(\d+))(?::(\d+))?\)?\s*$")
_CS_FRAME_RE = re.compile(r"^\s+at\s+([\w.<>\[\]]+)\(([^)]*)\)(?:\s+in\s+(.+?):line\s+(\d+))?\s*$")
_GO_FRAME_RE = re.compile(r"^\t?(.+?)\((.*)\)\s*$")
_GO_FILE_RE = re.compile(r"^\s+(/[\w./\-]+\.go):(\d+)")
_RUST_PANIC_RE = re.compile(r"^thread '.*' panicked at ([^:]+):(\d+):(\d+):")
_RUBY_FRAME_RE = re.compile(r"^\s+from (.+?):(\d+):in ['\x60](.+?)['\x60]\s*$")
_PHP_FRAME_RE = re.compile(r"^#(\d+)\s+(.+?)\[((\d+))\]:\s*(.*)$")
_PHP_FATAL_RE = re.compile(
    r"^(?:PHP )?(Fatal error|Parse error|Warning|Notice|Deprecated):\s*(?:Uncaught\s+)?(.+?)\s+in\s+(.+?)\s+on line\s+(\d+)"
)


def _header_candidates(line: str) -> List[str]:
    """Candidate header texts for a line: the line itself, and the text after a log separator."""
    cands: List[str] = []
    stripped = line.strip()
    if stripped:
        cands.append(stripped)
    if " - " in line:
        tail = line.rsplit(" - ", 1)[1].strip()
        if tail and tail not in cands:
            cands.append(tail)
    return cands


def _mk_frame(index: int, function: str, file: str, line=None, column=None, raw="") -> Frame:
    frame = Frame(index=index, function=function, file=file, line=line, column=column, raw=raw)
    frame.origin = classify_origin(function, file)
    frame.in_app = frame.origin in ("app", "test")
    return frame


def _split_type_message(text: str):
    if ":" in text:
        head, tail = text.split(":", 1)
        head = head.strip()
        if head and " " not in head and len(head) < 120:
            return head, tail.strip()
    return text.strip(), ""


def parse_java(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    for line in block.splitlines():
        if not line.strip():
            continue
        header = None
        for cand in _header_candidates(line):
            header = _JAVA_HEADER_RE.match(cand)
            if header:
                break
        if header:
            if current is not None:
                current.frames = frames
                errors.append(current)
            etype = header.group(1).strip()
            marker = ""
            raw_head = header.group(0)
            if raw_head.startswith("Caused by:"):
                marker = "Caused by"
            elif raw_head.startswith("Suppressed:"):
                marker = "Suppressed"
            current = ParsedError(
                language="java",
                error_type=etype,
                message=(header.group(2) or "").strip(),
                chain_index=len(errors),
                chain_marker=marker,
                raw=line.strip(),
            )
            frames = []
            continue
        fm = _JAVA_FRAME_RE.match(line)
        if fm and current is not None:
            fn, loc = fm.group(1), fm.group(2)
            fline = None
            ffile = ""
            if loc and loc not in ("Unknown Source", "Native Method"):
                if ":" in loc:
                    ffile, _, ln = loc.rpartition(":")
                    try:
                        fline = int(ln)
                    except ValueError:
                        ffile = loc
                        fline = None
                else:
                    ffile = loc
            frames.append(_mk_frame(len(frames), fn, ffile, fline, None, line.strip()))
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


_PY_EXCEPTION_RE = re.compile(
    r"^(?:[A-Za-z_][\w.]*\.)?[A-Za-z_]\w*(?:Error|Exception|Warning|Interrupt|Exit)\b"
)


def parse_python(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    marker = ""
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("Traceback (most recent call last)"):
            if current is not None:
                current.frames = frames
                errors.append(current)
            current = ParsedError(language="python", chain_index=len(errors), raw=stripped)
            frames = []
            marker = ""
            continue
        if "During handling of the above exception, another exception occurred" in stripped:
            if current is not None:
                current.frames = frames
                errors.append(current)
                current = None
            marker = "During handling"
            frames = []
            continue
        if "The above exception was the direct cause of the following exception" in stripped:
            if current is not None:
                current.frames = frames
                errors.append(current)
                current = None
            marker = "Direct cause"
            frames = []
            continue
        fm = _PY_FRAME_RE.match(line)
        if fm:
            if current is None:
                current = ParsedError(language="python", chain_index=len(errors), raw=stripped)
            frames.append(_mk_frame(len(frames), fm.group(3) or "<module>", fm.group(1),
                                    int(fm.group(2)), None, stripped))
            continue
        if current is not None and frames and line.startswith("    ") and not stripped.startswith("File "):
            continue
        exc_line = None
        for cand in _header_candidates(line):
            if _PY_EXCEPTION_RE.match(cand):
                exc_line = cand
                break
        if current is not None and exc_line:
            if current.error_type:
                current.frames = frames
                errors.append(current)
                current = None
                frames = []
            etype, msg = _split_type_message(exc_line)
            current = ParsedError(language="python", error_type=etype, message=msg,
                                  chain_index=len(errors), chain_marker=marker, raw=exc_line)
            marker = ""
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


def parse_javascript(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^at\s", stripped):
            fm = _JS_FRAME_RE.match(line)
            if fm:
                fn = (fm.group(1) or "").strip()
                loc = fm.group(2).strip()
                fline = int(fm.group(3)) if fm.group(3) else None
                col = int(fm.group(4)) if fm.group(4) else None
                if current is None:
                    current = ParsedError(language="javascript", chain_index=0, raw=stripped)
                frames.append(_mk_frame(len(frames), fn, loc, fline, col, stripped))
            continue
        header = None
        for cand in _header_candidates(line):
            if ":" in cand and re.match(r"^(?:Uncaught\s+)?[A-Za-z]*(?:Error|Exception|Warning)\b", cand):
                header = cand
                break
        if header:
            if current is not None and current.error_type:
                current.frames = frames
                errors.append(current)
                frames = []
            etype, msg = _split_type_message(header)
            if etype in ("Uncaught", ""):
                etype, msg = _split_type_message(header.replace("Uncaught", "", 1).strip())
            current = ParsedError(language="javascript", error_type=etype, message=msg,
                                  chain_index=len(errors), raw=header)
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


def parse_csharp(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        fm = _CS_FRAME_RE.match(line)
        if fm:
            fn = fm.group(1)
            ffile = fm.group(3) or ""
            fline = int(fm.group(4)) if fm.group(4) else None
            if current is None:
                current = ParsedError(language="csharp", chain_index=0, raw=stripped)
            frames.append(_mk_frame(len(frames), fn, ffile, fline, None, stripped))
            continue
        header = None
        for cand in _header_candidates(line):
            if re.match(r"^[A-Za-z_][\w.]*Exception\b", cand) or re.match(r"^[A-Za-z_][\w.]*Error\b", cand):
                header = cand
                break
        if header:
            if current is not None and current.error_type:
                current.frames = frames
                errors.append(current)
                frames = []
            etype, msg = _split_type_message(header)
            current = ParsedError(language="csharp", error_type=etype, message=msg,
                                  chain_index=len(errors), raw=header)
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


def parse_go(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    pending_func = ""
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("panic:") or stripped.startswith("fatal error:"):
            if current is not None:
                current.frames = frames
                errors.append(current)
                frames = []
            tail = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
            current = ParsedError(
                language="go",
                error_type="panic" if stripped.startswith("panic:") else "fatal error",
                message=tail,
                chain_index=len(errors),
                raw=stripped,
            )
            continue
        if stripped.startswith("goroutine ") and current is not None:
            continue
        gm = _GO_FRAME_RE.match(line)
        if gm and current is not None:
            pending_func = gm.group(1)
            continue
        gfm = _GO_FILE_RE.match(line)
        if gfm and current is not None:
            frames.append(_mk_frame(len(frames), pending_func, gfm.group(1), int(gfm.group(2)), None, stripped))
            pending_func = ""
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


def parse_rust(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pm = _RUST_PANIC_RE.match(stripped)
        if pm:
            if current is not None:
                current.frames = frames
                errors.append(current)
                frames = []
            current = ParsedError(language="rust", error_type="panicked", message="",
                                  chain_index=len(errors), raw=stripped)
            frames.append(_mk_frame(len(frames), "panic", pm.group(1), int(pm.group(2)),
                                    int(pm.group(3)), stripped))
            continue
        if current is not None and not current.message and stripped:
            current.message = stripped
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


def parse_ruby(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        rm = _RUBY_FRAME_RE.match(line)
        if rm:
            if current is None:
                current = ParsedError(language="ruby", chain_index=0, raw=stripped)
            frames.append(_mk_frame(len(frames), rm.group(3), rm.group(1), int(rm.group(2)), None, stripped))
            continue
        if current is None or not current.error_type:
            em = re.match(r"^(.*?)\s*\(([A-Za-z:]+Error)\)\s*$", stripped)
            if em:
                msg, etype = em.group(1).strip(), em.group(2)
            else:
                etype, msg = _split_type_message(stripped)
            current = ParsedError(language="ruby", error_type=etype, message=msg,
                                  chain_index=len(errors), raw=stripped)
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


def parse_php(block: str) -> List[ParsedError]:
    errors: List[ParsedError] = []
    current = None
    frames: List[Frame] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pm = _PHP_FATAL_RE.match(stripped)
        if pm:
            if current is not None:
                current.frames = frames
                errors.append(current)
                frames = []
            etype, msg = _split_type_message(pm.group(2))
            current = ParsedError(language="php", error_type=etype, message=msg,
                                  chain_index=len(errors), raw=stripped)
            continue
        fm = _PHP_FRAME_RE.match(line)
        if fm:
            if current is None:
                current = ParsedError(language="php", chain_index=0, raw=stripped)
            frames.append(_mk_frame(len(frames), fm.group(4), fm.group(2), int(fm.group(3)), None, stripped))
    if current is not None:
        current.frames = frames
        errors.append(current)
    return errors


def parse_generic(block: str) -> List[ParsedError]:
    lines = [l for l in block.splitlines() if l.strip()]
    if not lines:
        return []
    head = lines[0].strip()
    etype = ""
    msg = head
    tm = re.search(r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Warning))\b", head)
    if tm:
        etype = tm.group(1)
        msg = head[tm.end():].lstrip(": ").strip() or head
    else:
        hm = re.match(r"^([A-Za-z][\w.]*)\s*:\s*(.*)$", head)
        if hm and " " not in hm.group(1):
            etype = hm.group(1)
            msg = hm.group(2).strip()
    frames: List[Frame] = []
    for line in lines[1:]:
        gm = re.match(r"^\s*(?:at|in)\s+(.+?)\s*$", line)
        if gm:
            fn = gm.group(1)
            fl = None
            fm2 = re.search(r"([\w./\\-]+\.[a-z]{1,4}):(\d+)", fn)
            if fm2:
                fn = fn[: fm2.start()].strip() or fn
                fl = int(fm2.group(2))
            frames.append(_mk_frame(len(frames), fn, "", fl, None, line.strip()))
    return [ParsedError(language="unknown", error_type=etype, message=msg, frames=frames,
                        chain_index=0, raw=head)]


_LANG_PARSERS = {
    "java": parse_java,
    "python": parse_python,
    "javascript": parse_javascript,
    "csharp": parse_csharp,
    "go": parse_go,
    "rust": parse_rust,
    "ruby": parse_ruby,
    "php": parse_php,
}


def parse_error_block(block: str, language: str = "auto") -> List[ParsedError]:
    """Parse one trace block into a chain of ParsedError objects."""
    lang = detect_language(block) if language in ("auto", "", None) else language
    parser = _LANG_PARSERS.get(lang)
    errors = parser(block) if parser else []
    errors = [e for e in errors if e.error_type or e.message or e.frames]
    if not errors:
        errors = parse_generic(block)
    if errors and errors[0].language == "unknown" and lang != "unknown":
        errors[0].language = lang
    return errors


# ---------------------------------------------------------------------------
# log parsing
# ---------------------------------------------------------------------------

_LEVEL_RE = re.compile(r"\b(TRACE|DEBUG|INFO|INFORMATION|NOTICE|WARN|WARNING|ERROR|FATAL|CRITICAL|SEVERE)\b")
_TS_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}",
    r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
]
_CORRELATION_RE = re.compile(
    r"\b(?:request[_-]?id|trace[_-]?id|correlation[_-]?id|session[_-]?id|x-request-id|span[_-]?id|"
    r"req[_-]?id|rid|uuid|ticket[_-]?id)\b\s*[=:]\s*\S+",
    re.I,
)
_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|pwd|token|bearer|authorization|auth[_-]?header|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|credit[_-]?card|card[_-]?number|cvv|ssn)\b"
    r"\s*[=:]\s*\S+"
)
_PII_RE = re.compile(
    r"([\w.+-]+@[\w-]+\.[\w.]+)|(\+?\d[\d ().-]{8,}\d)|(\b\d{3}-\d{2}-\d{4}\b)"
    r"|(\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b)"
)


_FRAME_LINE_RE = re.compile(r"^\s*(?:at\s|File \"|#\d+\s|goroutine \d+|panic:)")


def parse_logs(text: str) -> List[LogEntry]:
    """Extract structured log entries from a pasted excerpt."""
    entries: List[LogEntry] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _FRAME_LINE_RE.match(line):
            continue
        lm = _LEVEL_RE.search(line)
        level = lm.group(1).upper() if lm else None
        ts = None
        for pat in _TS_PATTERNS:
            tmatch = re.search(pat, line)
            if tmatch:
                ts = tmatch.group(0)
                break
        if level is None and ts is None:
            continue
        logger = None
        lm2 = re.search(r"\b([a-z][\w]*\.[\w.]{3,})\b\s+-\s+", line)
        if lm2:
            logger = lm2.group(1)
        thread = None
        tm2 = re.search(r"\[([^\]]{2,40})\]", line)
        if tm2:
            thread = tm2.group(1)
        message = line.strip()
        if level:
            message = _LEVEL_RE.sub("", message, count=1).strip()
        if ts:
            message = message.replace(ts, "", 1).strip()
        if logger:
            message = message.replace(logger, "", 1).strip()
        message = message.lstrip("- ").strip()
        entries.append(LogEntry(timestamp=ts, level=level, logger=logger, thread=thread,
                                message=message, raw=line))
    return entries


# ---------------------------------------------------------------------------
# occurrence splitting
# ---------------------------------------------------------------------------


_HEAD_LINE_RE = re.compile(r"^(?:[A-Za-z_$][\w$]*\.)*[A-Z][\w$]*(?:Exception|Error|Throwable)\b")
_PY_HEAD_RE = re.compile(r"^Traceback \(most recent call last\)")
_PANIC_HEAD_RE = re.compile(r"^panic:")


def _looks_like_error(block: str) -> bool:
    if re.search(r"(Exception|Error|panic|Traceback|Fatal error|Uncaught)", block, re.I):
        return True
    if re.search(r"(?m)^\s*at [\w$.]+\(", block):
        return True
    if re.search(r'(?m)^\s+File "[^"]+", line \d+', block):
        return True
    return False


def split_occurrences(text: str) -> List[str]:
    """Split a paste into individual error occurrences."""
    if not text.strip():
        return []
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    blocks: List[str] = []
    if re.search(r"(?m)^\s*-{3,}\s*$", norm):
        parts = re.split(r"(?m)^\s*-{3,}\s*$", norm)
        blocks = [p.strip() for p in parts if p.strip()]
    else:
        blocks = [b.strip() for b in re.split(r"\n\s*\n", norm) if b.strip()]
        # A Go panic dump has a blank line between the panic header and the goroutine
        # stack, so re-join the goroutine block with the panic it belongs to.
        joined: List[str] = []
        for b in blocks:
            if joined and re.match(r"^goroutine \d+ \[", b):
                joined[-1] = joined[-1] + "\n\n" + b
            else:
                joined.append(b)
        blocks = joined

    expanded: List[str] = []
    for block in blocks:
        lines = block.splitlines()
        head_positions: List[int] = []
        offset = 0
        for line in lines:
            stripped = line.strip()
            # A "Caused by" / "Suppressed" header belongs to the chain above it,
            # so it must not start a new occurrence.
            chain_link = stripped.startswith("Caused by:") or stripped.startswith("Suppressed:")
            if not chain_link and (
                _HEAD_LINE_RE.match(line)
                or _PY_HEAD_RE.match(line)
                or _PANIC_HEAD_RE.match(line)
            ):
                head_positions.append(offset)
            offset += len(line) + 1
        if len(head_positions) > 1:
            for i, start in enumerate(head_positions):
                end = head_positions[i + 1] if i + 1 < len(head_positions) else len(block)
                piece = block[start:end].strip()
                if piece:
                    expanded.append(piece)
        else:
            expanded.append(block)

    return [b for b in expanded if _looks_like_error(b)]


# ---------------------------------------------------------------------------
# top-level parse
# ---------------------------------------------------------------------------


def parse_input(text: str, language: str = "auto") -> Dict[str, Any]:
    """Parse a paste into errors, log entries and detection metadata."""
    blocks = split_occurrences(text)
    occurrences = []
    errors: List[ParsedError] = []
    for block in blocks:
        chain = parse_error_block(block, language)
        if chain:
            occurrences.append({"raw": block, "errors": chain})
            errors.extend(chain)

    logs = parse_logs(text)
    lang = "unknown"
    if errors:
        counts: Dict[str, int] = {}
        for e in errors:
            counts[e.language] = counts.get(e.language, 0) + 1
        lang = max(counts.items(), key=lambda kv: kv[1])[0]
    elif logs:
        lang = detect_language(text)

    return {
        "errors": errors,
        "logs": logs,
        "language": lang,
        "occurrence_count": len(blocks),
        "occurrences": occurrences,
        "raw": text,
    }
