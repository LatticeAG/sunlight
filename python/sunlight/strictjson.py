"""Strict JSON parser for Sunlight wire/protocol documents (spec §2).

- UTF-8 input; BOM rejected; trailing non-whitespace rejected.
- Duplicate object keys rejected before object construction.
- Lone surrogates rejected; no replacement-character repair.
- Numbers are integers in [0, 9007199254740991] only: raw ``-0``, negatives,
  fractions, and exponents are rejected at the lexical level.
- Nesting deeper than 32 levels rejected.

All failures raise ``SunlightError("SCHEMA_INVALID")``.
"""

from __future__ import annotations

from .errors import SunlightError

MAX_JSON_DEPTH = 32
MAX_SAFE_UINT = 9007199254740991

_WS = " \t\n\r"
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _fail(msg: str) -> None:
    raise SunlightError("SCHEMA_INVALID", cause=ValueError(msg))


class _Parser:
    def __init__(self, src: str):
        self.s = src
        self.i = 0

    def parse(self):
        v = self.value(0)
        while self.i < len(self.s) and self.s[self.i] in _WS:
            self.i += 1
        if self.i != len(self.s):
            _fail("trailing bytes")
        return v

    def value(self, depth: int):
        if depth > MAX_JSON_DEPTH:
            _fail("depth limit")
        self._ws()
        if self.i >= len(self.s):
            _fail("unexpected end")
        ch = self.s[self.i]
        if ch == "{":
            return self.obj(depth)
        if ch == "[":
            return self.arr(depth)
        if ch == '"':
            return self.string()
        if ch == "t" and self.s.startswith("true", self.i):
            self.i += 4
            return True
        if ch == "f" and self.s.startswith("false", self.i):
            self.i += 5
            return False
        if ch == "n" and self.s.startswith("null", self.i):
            self.i += 4
            return None
        if ch == "-" or ch.isdigit():
            return self.number()
        _fail(f"unexpected character {ch!r}")

    def _ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in _WS:
            self.i += 1

    def obj(self, depth: int):
        self.i += 1
        out = {}
        self._ws()
        if self.i < len(self.s) and self.s[self.i] == "}":
            self.i += 1
            return out
        while True:
            self._ws()
            if self.i >= len(self.s) or self.s[self.i] != '"':
                _fail("expected object key")
            k = self.string()
            if k in out:
                _fail("duplicate object key")
            self._ws()
            if self.i >= len(self.s) or self.s[self.i] != ":":
                _fail("expected ':'")
            self.i += 1
            out[k] = self.value(depth + 1)
            self._ws()
            if self.i >= len(self.s):
                _fail("unterminated object")
            ch = self.s[self.i]
            if ch == ",":
                self.i += 1
                continue
            if ch == "}":
                self.i += 1
                return out
            _fail("expected ',' or '}'")

    def arr(self, depth: int):
        self.i += 1
        out = []
        self._ws()
        if self.i < len(self.s) and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            self._ws()
            if self.i >= len(self.s):
                _fail("unterminated array")
            ch = self.s[self.i]
            if ch == ",":
                self.i += 1
                continue
            if ch == "]":
                self.i += 1
                return out
            _fail("expected ',' or ']'")

    def string(self) -> str:
        self.i += 1
        out = []
        while True:
            if self.i >= len(self.s):
                _fail("unterminated string")
            ch = self.s[self.i]
            if ch == '"':
                self.i += 1
                return "".join(out)
            if ch == "\\":
                self.i += 1
                if self.i >= len(self.s):
                    _fail("unterminated escape")
                e = self.s[self.i]
                if e == "u":
                    hexs = self.s[self.i + 1 : self.i + 5]
                    if len(hexs) != 4 or any(c not in "0123456789abcdefABCDEF" for c in hexs):
                        _fail("bad \\u escape")
                    cp = int(hexs, 16)
                    self.i += 5
                    if 0xD800 <= cp <= 0xDBFF:
                        if self.s[self.i : self.i + 2] == "\\u":
                            lo = int(self.s[self.i + 2 : self.i + 6], 16)
                            if 0xDC00 <= lo <= 0xDFFF:
                                self.i += 6
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            else:
                                _fail("lone surrogate escape")
                        else:
                            _fail("lone surrogate escape")
                    elif 0xDC00 <= cp <= 0xDFFF:
                        _fail("lone surrogate escape")
                    out.append(chr(cp))
                    continue
                if e not in _ESCAPES:
                    _fail("bad escape")
                out.append(_ESCAPES[e])
                self.i += 1
                continue
            if ord(ch) < 0x20:
                _fail("control character in string")
            if 0xD800 <= ord(ch) <= 0xDFFF:
                _fail("lone surrogate")
            out.append(ch)
            self.i += 1

    def number(self):
        start = self.i
        if self.s[self.i] == "-":
            _fail("negative numbers outside protocol integer domain")
        while self.i < len(self.s) and self.s[self.i].isdigit():
            self.i += 1
        lexeme = self.s[start : self.i]
        if self.i < len(self.s) and self.s[self.i] in ".eE":
            _fail("non-integer number")
        if lexeme == "":
            _fail("empty number")
        if len(lexeme) > 1 and lexeme[0] == "0":
            _fail("leading zero")
        v = int(lexeme)
        if v > MAX_SAFE_UINT:
            _fail("number out of range")
        return v


def parse_strict_json(data) -> object:
    """Parse UTF-8 bytes strictly; ``SunlightError(SCHEMA_INVALID)`` on any failure."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if data[:3] == b"\xef\xbb\xbf":
        _fail("BOM rejected")
    try:
        src = bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise SunlightError("SCHEMA_INVALID", cause=e) from e
    return _Parser(src).parse()


def parse_strict_json_str(src: str):
    return parse_strict_json(src.encode("utf-8"))
