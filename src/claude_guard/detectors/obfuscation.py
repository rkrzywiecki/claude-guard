"""Text normalization and decoding shared by detectors to defeat common obfuscation.

- `strip_invisible` removes zero-width, soft-hyphen and Unicode tag characters and keeps an
  index map back to the original text, so findings on the cleaned text can still be redacted.
- `views` returns alternative readings of a text: NFKC-normalized, homoglyphs folded to Latin,
  leetspeak undone, and letter-spacing collapsed.
- `decoded_candidates` finds base64, hex and percent-encoded runs that decode to readable text.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

INVISIBLE = re.compile("[\U000e0000-\U000e007f\u200b\u200c\u200d\u2060\u180e\ufeff\u00ad]")

# Cyrillic and Greek letters that render like Latin ones.
_CONFUSABLES = str.maketrans(
    "аАвВеЕкКмМнНоОрРсСтТуУхХіІјЈѕЅԁɡαΑβΒεΕιΙκΚμΜνΝοΟρΡτΤυΥχΧ",
    "aAbBeEkKmMhHoOpPcCtTyYxXiIjJsSdgaAbBeEiIkKmMvNoOpPtTuYxX",
)
_LEET = str.maketrans("013457@$", "oieastas")
_LEET_TOKEN = re.compile(r"[A-Za-z0-9@$]*[A-Za-z][A-Za-z0-9@$]*")
_LEET_CHARS = re.compile(r"[013457@$]")
# Runs like "i g n o r e" or "i.g.n.o.r.e": single characters joined by one separator.
_SPACED = re.compile(r"(?<!\w)(?:\w[ .\-_*]){2,}\w(?!\w)")

MAX_CANDIDATES = 50
MAX_CANDIDATE_LENGTH = 20_000
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}[^%\s]{0,3}){4,}")


def strip_invisible(text: str) -> tuple[str, list[int]]:
    """Remove invisible characters; `mapping[i]` is the original index of cleaned char i."""
    kept: list[str] = []
    mapping: list[int] = []
    for index, char in enumerate(text):
        if not INVISIBLE.match(char):
            kept.append(char)
            mapping.append(index)
    return "".join(kept), mapping


def normalize(text: str) -> str:
    """Strip invisible characters and fold compatibility forms (e.g. full-width letters)."""
    return unicodedata.normalize("NFKC", INVISIBLE.sub("", text))


def fold_confusables(text: str) -> str:
    return text.translate(_CONFUSABLES)


def undo_leetspeak(text: str) -> str:
    """Translate digits/symbols inside words that also contain letters (`1gn0r3` -> `ignore`)."""

    def replace(match: re.Match[str]) -> str:
        token = match.group()
        return token.translate(_LEET) if _LEET_CHARS.search(token) else token

    return _LEET_TOKEN.sub(replace, text)


def collapse_spacing(text: str) -> str:
    return _SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group()), text)


def views(text: str) -> list[str]:
    """Distinct readings of `text`; the first is the plain normalized form."""
    base = normalize(text)
    folded = fold_confusables(base)
    result: list[str] = []
    for view in (base, folded, undo_leetspeak(folded), collapse_spacing(folded)):
        if view not in result:
            result.append(view)
    return result


@dataclass(frozen=True)
class Decoded:
    encoding: str
    text: str
    start: int
    end: int


def _readable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 6:
        return None
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t")
    letters = sum(1 for char in text if char.isalpha() or char == " ")
    if printable / len(text) < 0.95 or letters / len(text) < 0.5:
        return None
    return text


def _decode_base64(token: str) -> str | None:
    padded = token.rstrip("=")
    padded += "=" * (-len(padded) % 4)
    try:
        if "-" in token or "_" in token:
            data = base64.urlsafe_b64decode(padded)
        else:
            data = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _readable(data)


def decoded_candidates(
    text: str, encodings: tuple[str, ...] = ("base64", "hex", "percent")
) -> list[Decoded]:
    """Encoded runs in `text` that decode to readable text."""
    found: list[Decoded] = []
    patterns = {"base64": _BASE64, "hex": _HEX, "percent": _PERCENT}
    for encoding in encodings:
        for match in patterns[encoding].finditer(text):
            token = match.group()
            if len(token) > MAX_CANDIDATE_LENGTH:
                continue
            if encoding == "base64":
                decoded = _decode_base64(token)
            elif encoding == "hex":
                decoded = _readable(bytes.fromhex(token))
            else:
                decoded = unquote(token)
                decoded = decoded if decoded != token else None
            if decoded is not None:
                found.append(Decoded(encoding, decoded, match.start(), match.end()))
                if len(found) >= MAX_CANDIDATES:
                    return found
    return found
