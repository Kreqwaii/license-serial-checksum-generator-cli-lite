#!/usr/bin/env python3
"""License Serial & Checksum Generator CLI (Lite).

Zero-dependency Python 3.9+ standard-library utility to generate, batch-export,
deduplicate, and verify Crockford Base32 and Base36 software license keys with
Luhn-mod-32 and Luhn-mod-36 checksums.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

__version__ = "1.0.0"

CROCKFORD32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
BASE36_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CROCKFORD32_ALIASES: Dict[str, str] = {
    "I": "1",
    "L": "1",
    "O": "0",
}

ALPHABETS: Dict[str, str] = {
    "crockford32": CROCKFORD32_ALPHABET,
    "base36": BASE36_ALPHABET,
}
CHECKSUM_MODES: Tuple[str, ...] = ("auto", "luhn32", "luhn36", "none")
FAIL_ON_MODES: Tuple[str, ...] = ("invalid", "duplicate", "any", "none")
FORMAT_MODES: Tuple[str, ...] = ("text", "json", "csv")

DEFAULT_SEGMENTS = 4
DEFAULT_SEGMENT_LENGTH = 4
DEFAULT_SEPARATOR = "-"
DEFAULT_SEED = "license-v1"

KEY_COLUMN_CANDIDATES: Tuple[str, ...] = (
    "key",
    "license_key",
    "license",
    "serial",
    "serial_key",
    "code",
    "token",
)
PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")


class ConfigError(ValueError):
    """Raised on invalid CLI arguments or key specification."""


class InputError(OSError):
    """Raised on unreadable files or malformed CSV/TXT inputs."""


@dataclass(frozen=True)
class KeySpec:
    """Validated key generation and verification configuration."""

    prefix: str
    segments: Optional[int]
    segment_length: Optional[int]
    separator: str
    alphabet_name: str
    alphabet: str
    checksum_mode: str
    strict: bool = False

    @property
    def total_body_length(self) -> Optional[int]:
        if self.segments is not None and self.segment_length is not None:
            return self.segments * self.segment_length
        return None


@dataclass(frozen=True)
class GeneratedKey:
    """Generated license key record."""

    index: int
    key: str
    prefix: str
    mode: str
    alphabet: str
    checksum: str
    subject: str = ""


@dataclass(frozen=True)
class KeyVerificationResult:
    """Verification and deduplication status for a single license key."""

    line: int
    status: str  # VALID | DUPLICATE | INVALID
    valid: bool
    duplicate: bool
    normalized: bool
    raw_key: str
    canonical_key: str
    error_code: str
    message: str
    first_seen_line: Optional[int] = None


def resolve_alphabet_and_checksum(
    alphabet_name: Optional[str],
    checksum_mode: str,
) -> Tuple[str, str, str]:
    """Resolve and validate alphabet and checksum pairing."""
    if checksum_mode not in CHECKSUM_MODES:
        raise ConfigError(
            f"Unsupported checksum mode '{checksum_mode}'. Choose from: {', '.join(CHECKSUM_MODES)}."
        )

    if alphabet_name is None:
        resolved_alphabet_name = "base36" if checksum_mode == "luhn36" else "crockford32"
    else:
        if alphabet_name not in ALPHABETS:
            raise ConfigError(
                f"Unsupported alphabet '{alphabet_name}'. Choose from: {', '.join(ALPHABETS)}."
            )
        resolved_alphabet_name = alphabet_name

    if checksum_mode == "auto":
        resolved_checksum = "luhn32" if resolved_alphabet_name == "crockford32" else "luhn36"
    else:
        resolved_checksum = checksum_mode

    if resolved_checksum == "luhn32" and resolved_alphabet_name != "crockford32":
        raise ConfigError(
            "Checksum mode 'luhn32' requires alphabet 'crockford32'. Use 'luhn36' or 'none' for 'base36'."
        )
    if resolved_checksum == "luhn36" and resolved_alphabet_name != "base36":
        raise ConfigError(
            "Checksum mode 'luhn36' requires alphabet 'base36'. Use 'luhn32' or 'none' for 'crockford32'."
        )

    return resolved_alphabet_name, ALPHABETS[resolved_alphabet_name], resolved_checksum


def normalize_prefix(prefix: str, separator: str) -> str:
    """Validate and uppercase an optional product/tier prefix."""
    cleaned = prefix.strip().upper()
    if not cleaned:
        return ""
    if separator and separator in cleaned:
        raise ConfigError(
            f"Prefix '{cleaned}' must not contain the segment separator '{separator}'."
        )
    if not PREFIX_PATTERN.match(cleaned):
        raise ConfigError(
            f"Invalid prefix '{prefix}': only ASCII letters, digits, and '_' are allowed."
        )
    return cleaned


def validate_separator(separator: str) -> str:
    """Validate segment separator character/string."""
    if len(separator) > 2:
        raise ConfigError("Separator length must be at most 2 characters.")
    if any(ch.isalnum() or ch.isspace() for ch in separator):
        raise ConfigError("Separator must not contain alphanumeric or whitespace characters.")
    return separator


def build_key_spec(
    *,
    prefix: str = "",
    segments: Optional[int] = None,
    segment_length: Optional[int] = None,
    separator: str = DEFAULT_SEPARATOR,
    alphabet_name: Optional[str] = None,
    checksum_mode: str = "auto",
    strict: bool = False,
    for_generation: bool = False,
) -> KeySpec:
    """Create and validate a KeySpec."""
    validated_sep = validate_separator(separator)
    normalized_prefix = normalize_prefix(prefix, validated_sep)
    resolved_alpha_name, resolved_alpha, resolved_checksum = resolve_alphabet_and_checksum(
        alphabet_name, checksum_mode
    )

    eff_segments = DEFAULT_SEGMENTS if (for_generation and segments is None) else segments
    eff_seg_len = DEFAULT_SEGMENT_LENGTH if (for_generation and segment_length is None) else segment_length

    if eff_segments is not None and eff_segments < 1:
        raise ConfigError("--segments must be >= 1.")
    if eff_seg_len is not None and eff_seg_len < 1:
        raise ConfigError("--segment-length must be >= 1.")

    if eff_segments is not None and eff_seg_len is not None:
        total_len = eff_segments * eff_seg_len
        min_len = 2 if resolved_checksum != "none" else 1
        if total_len < min_len:
            raise ConfigError(
                f"Key body length ({total_len}) must be at least {min_len} when checksum='{resolved_checksum}'."
            )

    return KeySpec(
        prefix=normalized_prefix,
        segments=eff_segments,
        segment_length=eff_seg_len,
        separator=validated_sep,
        alphabet_name=resolved_alpha_name,
        alphabet=resolved_alpha,
        checksum_mode=resolved_checksum,
        strict=strict,
    )


def luhn_mod_n_check_char(payload: str, alphabet: str) -> str:
    """Compute the Luhn mod N check digit for a payload string."""
    if not payload:
        raise ValueError("Payload must not be empty when computing Luhn check character.")
    n = len(alphabet)
    char_to_val = {ch: idx for idx, ch in enumerate(alphabet)}

    factor = 2
    total = 0
    for ch in reversed(payload):
        if ch not in char_to_val:
            raise ValueError(f"Character '{ch}' is outside alphabet of size {n}.")
        addend = factor * char_to_val[ch]
        addend = (addend // n) + (addend % n)
        total += addend
        factor = 1 if factor == 2 else 2

    check_code = (n - (total % n)) % n
    return alphabet[check_code]


def verify_luhn_mod_n(full_body: str, alphabet: str) -> bool:
    """Verify a full key body ending with its Luhn mod N check character."""
    if len(full_body) < 2:
        return False
    n = len(alphabet)
    char_to_val = {ch: idx for idx, ch in enumerate(alphabet)}

    factor = 1
    total = 0
    for ch in reversed(full_body):
        if ch not in char_to_val:
            return False
        addend = factor * char_to_val[ch]
        addend = (addend // n) + (addend % n)
        total += addend
        factor = 2 if factor == 1 else 1

    return (total % n) == 0


def format_body(
    body: str,
    *,
    segments: int,
    segment_length: int,
    separator: str,
    prefix: str = "",
) -> str:
    """Format a canonical body string into prefixed, separated segments."""
    expected_len = segments * segment_length
    if len(body) != expected_len:
        raise ValueError(f"Body length {len(body)} does not match {segments}x{segment_length}={expected_len}.")
    chunks = [body[i : i + segment_length] for i in range(0, expected_len, segment_length)]
    joined = separator.join(chunks)
    if prefix:
        return f"{prefix}{separator}{joined}" if separator else f"{prefix}{joined}"
    return joined


def _derive_hmac_payload(
    *,
    secret: str,
    seed: str,
    spec: KeySpec,
    identifier: str,
    payload_len: int,
) -> str:
    """Derive a deterministic, bias-free payload using HMAC-SHA256 in counter mode."""
    assert spec.segments is not None and spec.segment_length is not None
    secret_bytes = secret.encode("utf-8")
    n = len(spec.alphabet)
    rejection_limit = (256 // n) * n
    domain = (
        f"serial-keygen:v1|seed={seed}|prefix={spec.prefix}|alphabet={spec.alphabet_name}|"
        f"checksum={spec.checksum_mode}|segments={spec.segments}|"
        f"segment_length={spec.segment_length}|id={identifier}"
    )

    chars: List[str] = []
    counter = 0
    while len(chars) < payload_len:
        msg = f"{domain}|ctr={counter}".encode("utf-8")
        digest = hmac.new(secret_bytes, msg, hashlib.sha256).digest()
        for byte in digest:
            if byte < rejection_limit:
                chars.append(spec.alphabet[byte % n])
                if len(chars) == payload_len:
                    break
        counter += 1
    return "".join(chars)


def _generate_random_payload(alphabet: str, payload_len: int) -> str:
    """Generate a CSPRNG payload using secrets.choice."""
    return "".join(secrets.choice(alphabet) for _ in range(payload_len))


def _body_with_checksum(payload: str, spec: KeySpec) -> str:
    """Append check digit if checksum is active."""
    if spec.checksum_mode == "none":
        return payload
    return payload + luhn_mod_n_check_char(payload, spec.alphabet)


def extract_canonical_body(raw_key: str, spec: KeySpec) -> Optional[str]:
    """Return canonical body if raw_key passes verification under spec, else None."""
    result = verify_key(raw_key, spec=spec)
    if not result.valid:
        return None
    canonical = result.canonical_key
    if spec.prefix:
        tag = f"{spec.prefix}{spec.separator}"
        canonical = canonical[len(tag) :]
    if spec.separator:
        return canonical.replace(spec.separator, "")
    return canonical


def generate_keys(
    spec: KeySpec,
    *,
    count: int = 1,
    secret: Optional[str] = None,
    seed: str = DEFAULT_SEED,
    start_index: int = 1,
    subjects: Optional[Sequence[str]] = None,
    exclude_keys: Iterable[str] = (),
) -> List[GeneratedKey]:
    """Generate unique CSPRNG or deterministic HMAC-SHA256 license keys."""
    if spec.segments is None or spec.segment_length is None:
        raise ConfigError("Both segments and segment_length must be specified for key generation.")

    total_len = spec.segments * spec.segment_length
    payload_len = total_len - 1 if spec.checksum_mode != "none" else total_len

    if secret is not None:
        if secret == "":
            raise ConfigError("HMAC --secret must not be empty.")
        if subjects:
            targets: List[Tuple[int, str, str]] = [
                (idx, f"sub:{sub}", sub) for idx, sub in enumerate(subjects, start=1)
            ]
        else:
            if count < 1:
                raise ConfigError("--count must be >= 1.")
            targets = [
                (i, f"idx:{start_index + i - 1}", "") for i in range(1, count + 1)
            ]

        generated: List[GeneratedKey] = []
        for idx, identifier, subject in targets:
            payload = _derive_hmac_payload(
                secret=secret,
                seed=seed,
                spec=spec,
                identifier=identifier,
                payload_len=payload_len,
            )
            body = _body_with_checksum(payload, spec)
            formatted = format_body(
                body,
                segments=spec.segments,
                segment_length=spec.segment_length,
                separator=spec.separator,
                prefix=spec.prefix,
            )
            generated.append(
                GeneratedKey(
                    index=idx,
                    key=formatted,
                    prefix=spec.prefix,
                    mode="hmac-sha256",
                    alphabet=spec.alphabet_name,
                    checksum=spec.checksum_mode,
                    subject=subject,
                )
            )
        return generated

    # CSPRNG mode using secrets
    if subjects:
        raise ConfigError("--subject / --subjects-file requires --secret for deterministic derivation.")
    if count < 1:
        raise ConfigError("--count must be >= 1.")

    excluded_bodies: Set[str] = set()
    for existing in exclude_keys:
        body = extract_canonical_body(existing, spec)
        if body is not None:
            excluded_bodies.add(body)
        else:
            # Also normalize raw stripped body if compatible so duplicates are still skipped
            cleaned = existing.strip().upper()
            if spec.prefix:
                tag = f"{spec.prefix}{spec.separator}"
                if cleaned.startswith(tag):
                    cleaned = cleaned[len(tag) :]
            if spec.separator:
                cleaned = cleaned.replace(spec.separator, "")
            excluded_bodies.add(cleaned)

    keyspace_size = len(spec.alphabet) ** payload_len
    if count > keyspace_size:
        raise ConfigError(
            f"Cannot generate {count} unique keys: keyspace for payload length {payload_len} "
            f"in '{spec.alphabet_name}' only contains {keyspace_size} distinct keys."
        )

    seen_bodies: Set[str] = set(excluded_bodies)
    generated_list: List[GeneratedKey] = []
    max_attempts = max(count * 50, 1000)
    attempts = 0

    while len(generated_list) < count:
        attempts += 1
        if attempts > max_attempts:
            raise ConfigError(
                f"Exhausted {max_attempts} generation attempts before reaching {count} unique keys "
                f"(keyspace={keyspace_size}, excluded={len(excluded_bodies)})."
            )
        payload = _generate_random_payload(spec.alphabet, payload_len)
        body = _body_with_checksum(payload, spec)
        if body in seen_bodies:
            continue
        seen_bodies.add(body)
        formatted = format_body(
            body,
            segments=spec.segments,
            segment_length=spec.segment_length,
            separator=spec.separator,
            prefix=spec.prefix,
        )
        generated_list.append(
            GeneratedKey(
                index=len(generated_list) + 1,
                key=formatted,
                prefix=spec.prefix,
                mode="secrets",
                alphabet=spec.alphabet_name,
                checksum=spec.checksum_mode,
                subject="",
            )
        )

    return generated_list


def verify_key(
    raw_key: str,
    *,
    spec: KeySpec,
    line: int = 1,
) -> KeyVerificationResult:
    """Validate format, prefix, alphabet, Crockford aliases, and Luhn checksum."""
    candidate = raw_key.strip()
    if not candidate:
        return KeyVerificationResult(
            line=line,
            status="INVALID",
            valid=False,
            duplicate=False,
            normalized=False,
            raw_key=raw_key,
            canonical_key="",
            error_code="EMPTY_KEY",
            message="Key string is empty.",
        )

    normalized = False
    body_part = candidate

    if spec.prefix:
        expected_tag = f"{spec.prefix}{spec.separator}"
        if spec.strict:
            if not candidate.startswith(expected_tag):
                return KeyVerificationResult(
                    line=line,
                    status="INVALID",
                    valid=False,
                    duplicate=False,
                    normalized=False,
                    raw_key=raw_key,
                    canonical_key="",
                    error_code="PREFIX_MISMATCH",
                    message=f"Expected strict prefix '{expected_tag}'.",
                )
        else:
            if not candidate.upper().startswith(expected_tag):
                return KeyVerificationResult(
                    line=line,
                    status="INVALID",
                    valid=False,
                    duplicate=False,
                    normalized=False,
                    raw_key=raw_key,
                    canonical_key="",
                    error_code="PREFIX_MISMATCH",
                    message=f"Expected prefix '{expected_tag}'.",
                )
            if candidate[: len(expected_tag)] != expected_tag:
                normalized = True
        body_part = candidate[len(expected_tag) :]

    if not body_part:
        return KeyVerificationResult(
            line=line,
            status="INVALID",
            valid=False,
            duplicate=False,
            normalized=normalized,
            raw_key=raw_key,
            canonical_key="",
            error_code="EMPTY_BODY",
            message="Key has no body after prefix.",
        )

    if spec.separator:
        parts = body_part.split(spec.separator)
        if any(part == "" for part in parts):
            return KeyVerificationResult(
                line=line,
                status="INVALID",
                valid=False,
                duplicate=False,
                normalized=normalized,
                raw_key=raw_key,
                canonical_key="",
                error_code="MALFORMED_SEGMENTS",
                message=f"Key contains empty segment(s) around separator '{spec.separator}'.",
            )
        if spec.segments is not None and len(parts) != spec.segments:
            return KeyVerificationResult(
                line=line,
                status="INVALID",
                valid=False,
                duplicate=False,
                normalized=normalized,
                raw_key=raw_key,
                canonical_key="",
                error_code="SEGMENT_COUNT_MISMATCH",
                message=f"Expected {spec.segments} segment(s), got {len(parts)}.",
            )
        if spec.segment_length is not None:
            if any(len(part) != spec.segment_length for part in parts):
                return KeyVerificationResult(
                    line=line,
                    status="INVALID",
                    valid=False,
                    duplicate=False,
                    normalized=normalized,
                    raw_key=raw_key,
                    canonical_key="",
                    error_code="SEGMENT_LENGTH_MISMATCH",
                    message=f"Expected each segment to have length {spec.segment_length}.",
                )
        elif len(parts) > 1 and len({len(part) for part in parts}) > 1:
            lengths = ", ".join(str(len(p)) for p in parts)
            return KeyVerificationResult(
                line=line,
                status="INVALID",
                valid=False,
                duplicate=False,
                normalized=normalized,
                raw_key=raw_key,
                canonical_key="",
                error_code="SEGMENT_LENGTH_MISMATCH",
                message=f"Inconsistent segment lengths ({lengths}).",
            )

        segment_lengths = [len(p) for p in parts]
        raw_body = "".join(parts)
    else:
        if spec.total_body_length is not None and len(body_part) != spec.total_body_length:
            return KeyVerificationResult(
                line=line,
                status="INVALID",
                valid=False,
                duplicate=False,
                normalized=normalized,
                raw_key=raw_key,
                canonical_key="",
                error_code="LENGTH_MISMATCH",
                message=f"Expected body length {spec.total_body_length}, got {len(body_part)}.",
            )
        segment_lengths = [len(body_part)]
        raw_body = body_part

    min_body_len = 2 if spec.checksum_mode != "none" else 1
    if len(raw_body) < min_body_len:
        return KeyVerificationResult(
            line=line,
            status="INVALID",
            valid=False,
            duplicate=False,
            normalized=normalized,
            raw_key=raw_key,
            canonical_key="",
            error_code="TOO_SHORT",
            message=f"Key body length {len(raw_body)} is below minimum {min_body_len}.",
        )

    allowed_set = set(spec.alphabet)
    canonical_chars: List[str] = []
    for ch in raw_body:
        if spec.strict:
            if ch not in allowed_set:
                return KeyVerificationResult(
                    line=line,
                    status="INVALID",
                    valid=False,
                    duplicate=False,
                    normalized=normalized,
                    raw_key=raw_key,
                    canonical_key="",
                    error_code="INVALID_CHARACTER",
                    message=f"Invalid character '{ch}' for strict '{spec.alphabet_name}' alphabet.",
                )
            canonical_chars.append(ch)
        else:
            upper_ch = ch.upper()
            mapped_ch = upper_ch
            if spec.alphabet_name == "crockford32" and upper_ch in CROCKFORD32_ALIASES:
                mapped_ch = CROCKFORD32_ALIASES[upper_ch]
            if mapped_ch != ch:
                normalized = True
            if mapped_ch not in allowed_set:
                return KeyVerificationResult(
                    line=line,
                    status="INVALID",
                    valid=False,
                    duplicate=False,
                    normalized=normalized,
                    raw_key=raw_key,
                    canonical_key="",
                    error_code="INVALID_CHARACTER",
                    message=f"Invalid character '{ch}' for '{spec.alphabet_name}' alphabet.",
                )
            canonical_chars.append(mapped_ch)

    canonical_body = "".join(canonical_chars)

    if spec.checksum_mode != "none":
        if not verify_luhn_mod_n(canonical_body, spec.alphabet):
            return KeyVerificationResult(
                line=line,
                status="INVALID",
                valid=False,
                duplicate=False,
                normalized=normalized,
                raw_key=raw_key,
                canonical_key="",
                error_code="INVALID_CHECKSUM",
                message=f"Failed {spec.checksum_mode} checksum verification.",
            )

    # Reconstruct canonical formatted key preserving segment structure
    chunks: List[str] = []
    offset = 0
    for seg_len in segment_lengths:
        chunks.append(canonical_body[offset : offset + seg_len])
        offset += seg_len
    canonical_joined = spec.separator.join(chunks) if spec.separator else canonical_body
    if spec.prefix:
        canonical_key = (
            f"{spec.prefix}{spec.separator}{canonical_joined}"
            if spec.separator
            else f"{spec.prefix}{canonical_joined}"
        )
    else:
        canonical_key = canonical_joined

    msg = "OK (normalized)" if normalized else "OK"
    return KeyVerificationResult(
        line=line,
        status="VALID",
        valid=True,
        duplicate=False,
        normalized=normalized,
        raw_key=candidate,
        canonical_key=canonical_key,
        error_code="",
        message=msg,
    )


def audit_key_entries(
    entries: Iterable[Tuple[int, str]],
    *,
    spec: KeySpec,
) -> Dict[str, Any]:
    """Verify and deduplicate an iterable of (line_number, raw_key) pairs."""
    seen_canonical: Dict[str, int] = {}
    results: List[KeyVerificationResult] = []

    unique_valid = 0
    duplicates = 0
    invalid = 0
    normalized_count = 0

    for line_no, raw_key in entries:
        res = verify_key(raw_key, spec=spec, line=line_no)
        if not res.valid:
            invalid += 1
            results.append(res)
            continue

        if res.normalized:
            normalized_count += 1

        if res.canonical_key in seen_canonical:
            first_line = seen_canonical[res.canonical_key]
            duplicates += 1
            results.append(
                KeyVerificationResult(
                    line=line_no,
                    status="DUPLICATE",
                    valid=True,
                    duplicate=True,
                    normalized=res.normalized,
                    raw_key=res.raw_key,
                    canonical_key=res.canonical_key,
                    error_code="DUPLICATE_KEY",
                    message=f"Duplicate canonical key (first seen at line {first_line}).",
                    first_seen_line=first_line,
                )
            )
        else:
            seen_canonical[res.canonical_key] = line_no
            unique_valid += 1
            results.append(res)

    total_entries = len(results)
    summary = {
        "total_entries": total_entries,
        "valid_total": unique_valid + duplicates,
        "unique_valid": unique_valid,
        "duplicates": duplicates,
        "invalid": invalid,
        "normalized_count": normalized_count,
        "alphabet": spec.alphabet_name,
        "checksum": spec.checksum_mode,
        "prefix": spec.prefix,
        "strict": spec.strict,
    }
    return {
        "summary": summary,
        "results": results,
    }


def _read_text_source(path_str: str) -> str:
    """Read UTF-8 (with optional BOM) text from file path or '-' for stdin."""
    if path_str == "-":
        return sys.stdin.read()
    path = Path(path_str)
    if not path.exists():
        raise InputError(f"Input file not found: '{path_str}'.")
    if not path.is_file():
        raise InputError(f"Input path is not a file: '{path_str}'.")
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"Unable to read '{path_str}': {exc}") from exc


def _looks_like_csv(text: str, path_str: str) -> bool:
    """Determine whether input should be parsed as CSV vs line-delimited TXT."""
    if path_str != "-" and Path(path_str).suffix.lower() == ".csv":
        return True
    if path_str != "-" and Path(path_str).suffix.lower() == ".txt":
        return False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "," in stripped or ";" in stripped:
            return True
        lowered = stripped.lower()
        return lowered in KEY_COLUMN_CANDIDATES
    return False


def _detect_csv_delimiter(sample: str) -> str:
    """Detect comma vs semicolon delimiter for CSV content."""
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        return dialect.delimiter
    except csv.Error:
        return ";" if sample.count(";") > sample.count(",") else ","


def load_key_entries(path_str: str, *, column: Optional[str] = None) -> List[Tuple[int, str]]:
    """Load (1-based line/row, raw_key) entries from a TXT or CSV file or stdin."""
    text = _read_text_source(path_str)
    is_csv = _looks_like_csv(text, path_str) or (column is not None)

    if not is_csv:
        entries: List[Tuple[int, str]] = []
        for idx, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            entries.append((idx, stripped))
        return entries

    # CSV parsing
    lines = text.splitlines()
    if not lines:
        return []
    sample = "\n".join(lines[:10])
    delimiter = _detect_csv_delimiter(sample)
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows = list(reader)
    if not rows:
        return []

    first_non_empty_idx: Optional[int] = None
    for idx, row in enumerate(rows):
        if row and any(cell.strip() for cell in row):
            first_non_empty_idx = idx
            break
    if first_non_empty_idx is None:
        return []

    first_row = [cell.strip() for cell in rows[first_non_empty_idx]]
    lowered_first = [cell.lower() for cell in first_row]

    col_idx: Optional[int] = None
    skip_first_as_header = False

    if column is not None:
        col_stripped = column.strip()
        if col_stripped.isdigit():
            col_idx = int(col_stripped)
            if col_idx >= len(first_row):
                raise InputError(
                    f"CSV column index {col_idx} out of range (row has {len(first_row)} column(s))."
                )
            if lowered_first[col_idx] in KEY_COLUMN_CANDIDATES:
                skip_first_as_header = True
        else:
            target = col_stripped.lower()
            if target in lowered_first:
                col_idx = lowered_first.index(target)
                skip_first_as_header = True
            else:
                raise InputError(
                    f"CSV column '{column}' not found in header: {first_row}."
                )
    else:
        for candidate in KEY_COLUMN_CANDIDATES:
            if candidate in lowered_first:
                col_idx = lowered_first.index(candidate)
                skip_first_as_header = True
                break
        if col_idx is None:
            if len(first_row) == 1:
                col_idx = 0
            else:
                raise InputError(
                    "Multi-column CSV lacks a recognized key header "
                    f"({', '.join(KEY_COLUMN_CANDIDATES)}). Specify --column <name|index>."
                )

    assert col_idx is not None
    start_row_idx = first_non_empty_idx + 1 if skip_first_as_header else first_non_empty_idx

    csv_entries: List[Tuple[int, str]] = []
    for row_idx in range(start_row_idx, len(rows)):
        row = rows[row_idx]
        if not row or not any(cell.strip() for cell in row):
            continue
        val = row[col_idx].strip() if col_idx < len(row) else ""
        csv_entries.append((row_idx + 1, val))
    return csv_entries


def load_subjects_file(path_str: str) -> List[str]:
    """Load non-empty, non-comment subject identifiers from a file or stdin."""
    text = _read_text_source(path_str)
    subjects: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        subjects.append(stripped)
    if not subjects:
        raise InputError(f"Subjects file '{path_str}' contains no valid subject entries.")
    return subjects


def write_deduped_keys(
    path_str: str,
    results: Sequence[KeyVerificationResult],
    spec: KeySpec,
) -> int:
    """Write unique valid canonical keys from an audit report to TXT or CSV."""
    unique_keys = [r.canonical_key for r in results if r.status == "VALID"]
    out_path = Path(path_str)
    if out_path.parent and str(out_path.parent) != ".":
        out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == ".csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["index", "key", "prefix", "alphabet", "checksum"])
        for idx, key in enumerate(unique_keys, start=1):
            writer.writerow([idx, key, spec.prefix, spec.alphabet_name, spec.checksum_mode])
        out_path.write_text(buf.getvalue(), encoding="utf-8")
    else:
        content = "\n".join(unique_keys) + ("\n" if unique_keys else "")
        out_path.write_text(content, encoding="utf-8")

    return len(unique_keys)


def _render_ascii_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """Render an aligned ASCII table with pipe delimiters."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    def fmt_row(cells: Sequence[str]) -> str:
        return " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    sep_line = "-+-".join("-" * w for w in widths)
    lines = [fmt_row(headers), sep_line]
    for row in rows:
        lines.append(fmt_row(row))
    return "\n".join(lines)


def format_generated_output(
    keys: Sequence[GeneratedKey],
    spec: KeySpec,
    *,
    fmt: str,
    keys_only: bool = False,
) -> str:
    """Render generated keys as text, JSON, or CSV."""
    if fmt == "json":
        payload = {
            "summary": {
                "count": len(keys),
                "mode": keys[0].mode if keys else "none",
                "prefix": spec.prefix,
                "segments": spec.segments,
                "segment_length": spec.segment_length,
                "separator": spec.separator,
                "alphabet": spec.alphabet_name,
                "checksum": spec.checksum_mode,
            },
            "keys": [asdict(k) for k in keys],
        }
        return json.dumps(payload, indent=2) + "\n"

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["index", "key", "prefix", "mode", "alphabet", "checksum", "subject"])
        for item in keys:
            writer.writerow(
                [
                    item.index,
                    item.key,
                    item.prefix,
                    item.mode,
                    item.alphabet,
                    item.checksum,
                    item.subject,
                ]
            )
        return buf.getvalue()

    # text format
    if keys_only:
        return "\n".join(k.key for k in keys) + ("\n" if keys else "")

    mode_label = keys[0].mode if keys else "none"
    header_line = (
        f"Generated {len(keys)} key(s) | Mode: {mode_label} | "
        f"Alphabet: {spec.alphabet_name} | Checksum: {spec.checksum_mode} | "
        f"Prefix: {spec.prefix or '(none)'}"
    )
    has_subjects = any(k.subject for k in keys)
    if has_subjects:
        headers = ["#", "Key", "Subject", "Checksum"]
        rows = [[str(k.index), k.key, k.subject or "-", k.checksum] for k in keys]
    else:
        headers = ["#", "Key", "Mode", "Checksum"]
        rows = [[str(k.index), k.key, k.mode, k.checksum] for k in keys]
    return header_line + "\n\n" + _render_ascii_table(headers, rows) + "\n"


def format_audit_output(
    report: Dict[str, Any],
    *,
    fmt: str,
    only_issues: bool = False,
    dedupe_written: Optional[Tuple[str, int]] = None,
) -> str:
    """Render verification/audit results as text, JSON, or CSV."""
    summary = report["summary"]
    all_results: List[KeyVerificationResult] = report["results"]
    display_results = (
        [r for r in all_results if r.status != "VALID"] if only_issues else all_results
    )

    if fmt == "json":
        payload: Dict[str, Any] = {
            "summary": summary,
            "results": [asdict(r) for r in display_results],
        }
        if dedupe_written is not None:
            payload["dedupe_output"] = {
                "path": dedupe_written[0],
                "written_count": dedupe_written[1],
            }
        return json.dumps(payload, indent=2) + "\n"

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(
            [
                "line",
                "status",
                "valid",
                "duplicate",
                "normalized",
                "raw_key",
                "canonical_key",
                "error_code",
                "message",
                "first_seen_line",
            ]
        )
        for item in display_results:
            writer.writerow(
                [
                    item.line,
                    item.status,
                    str(item.valid).lower(),
                    str(item.duplicate).lower(),
                    str(item.normalized).lower(),
                    item.raw_key,
                    item.canonical_key,
                    item.error_code,
                    item.message,
                    item.first_seen_line if item.first_seen_line is not None else "",
                ]
            )
        return buf.getvalue()

    # text format
    status_label = (
        "PASS"
        if summary["invalid"] == 0 and summary["duplicates"] == 0
        else ("WARN" if summary["invalid"] == 0 else "FAIL")
    )
    summary_line = (
        f"Key Audit Summary | Total: {summary['total_entries']} | "
        f"Unique Valid: {summary['unique_valid']} | Duplicates: {summary['duplicates']} | "
        f"Invalid: {summary['invalid']} | Normalized: {summary['normalized_count']} | "
        f"Status: {status_label}"
    )
    lines = [summary_line]
    if dedupe_written is not None:
        lines.append(f"Deduplicated valid keys written: {dedupe_written[1]} -> {dedupe_written[0]}")
    lines.append("")

    if not display_results:
        lines.append("No matching records to display.")
        return "\n".join(lines) + "\n"

    headers = ["Line", "Status", "Raw Key", "Canonical Key", "Code", "Details"]
    rows = [
        [
            str(r.line),
            r.status,
            r.raw_key,
            r.canonical_key or "-",
            r.error_code or "-",
            r.message,
        ]
        for r in display_results
    ]
    lines.append(_render_ascii_table(headers, rows))
    return "\n".join(lines) + "\n"


def should_fail(summary: Dict[str, Any], fail_on: str) -> bool:
    """Evaluate --fail-on policy against audit summary."""
    if fail_on == "none":
        return False
    if fail_on == "invalid":
        return summary["invalid"] > 0
    if fail_on == "duplicate":
        return summary["duplicates"] > 0
    if fail_on == "any":
        return summary["invalid"] > 0 or summary["duplicates"] > 0
    raise ConfigError(f"Unknown --fail-on policy '{fail_on}'.")


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="serial_keygen.py",
        description=(
            "Zero-dependency CLI to generate, batch-export, deduplicate, and verify "
            "Crockford-32 and Base-36 software license keys with Luhn-mod-32/36 checksums."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--generate",
        action="store_true",
        help="Generate secure (secrets) or deterministic (HMAC-SHA256) license keys.",
    )
    mode_group.add_argument(
        "--verify",
        nargs="+",
        metavar="KEY",
        help="Verify one or more individual license keys (pass '-' to read from stdin).",
    )
    mode_group.add_argument(
        "--audit-file",
        metavar="PATH",
        help="Audit and deduplicate a bulk TXT or CSV list of license keys ('-' for stdin).",
    )

    key_group = parser.add_argument_group("Key Format & Checksum Options")
    key_group.add_argument(
        "--prefix",
        default="",
        help="Optional product/tier prefix (e.g. PRO, SAAS). Default: none.",
    )
    key_group.add_argument(
        "--segments",
        type=int,
        default=None,
        help=f"Number of body segments (default: {DEFAULT_SEGMENTS} when generating).",
    )
    key_group.add_argument(
        "--segment-length",
        type=int,
        default=None,
        help=f"Characters per segment (default: {DEFAULT_SEGMENT_LENGTH} when generating).",
    )
    key_group.add_argument(
        "--separator",
        default=DEFAULT_SEPARATOR,
        help=f"Segment separator (default: '{DEFAULT_SEPARATOR}', pass '' for none).",
    )
    key_group.add_argument(
        "--alphabet",
        choices=tuple(ALPHABETS.keys()),
        default=None,
        help="Key body alphabet: 'crockford32' (default) or 'base36'.",
    )
    key_group.add_argument(
        "--checksum",
        choices=CHECKSUM_MODES,
        default="auto",
        help="Checksum algorithm: 'auto' (luhn32 for crockford32, luhn36 for base36), 'luhn32', 'luhn36', or 'none'.",
    )
    key_group.add_argument(
        "--strict",
        action="store_true",
        help="Require exact uppercase characters and disallow Crockford I/L->1 and O->0 aliases during verification.",
    )

    gen_group = parser.add_argument_group("Generation Options (--generate)")
    gen_group.add_argument(
        "-n",
        "--count",
        type=int,
        default=None,
        help="Number of keys to generate (default: 1).",
    )
    gen_group.add_argument(
        "--secret",
        default=None,
        help="HMAC-SHA256 secret for deterministic generation (omit for CSPRNG via secrets).",
    )
    gen_group.add_argument(
        "--seed",
        default=DEFAULT_SEED,
        help=f"Deterministic domain seed/namespace used with --secret (default: '{DEFAULT_SEED}').",
    )
    gen_group.add_argument(
        "--start-index",
        type=int,
        default=1,
        help="Starting sequence index for deterministic batch generation (default: 1).",
    )
    gen_group.add_argument(
        "--subject",
        action="append",
        default=[],
        help="Subject/order identifier for deterministic HMAC key derivation (repeatable).",
    )
    gen_group.add_argument(
        "--subjects-file",
        default=None,
        help="Path to file with one subject identifier per line for deterministic derivation.",
    )
    gen_group.add_argument(
        "--exclude-file",
        default=None,
        help="Existing TXT/CSV key list to exclude from random CSPRNG generation.",
    )
    gen_group.add_argument(
        "--keys-only",
        action="store_true",
        help="In '--generate --format text', print raw keys one per line without headers.",
    )

    audit_group = parser.add_argument_group("Audit & Output Options")
    audit_group.add_argument(
        "--column",
        default=None,
        help="CSV column name or 0-based index for --audit-file / --exclude-file.",
    )
    audit_group.add_argument(
        "--dedupe-out",
        default=None,
        help="Write deduplicated valid canonical keys to a .txt or .csv file.",
    )
    audit_group.add_argument(
        "--only-issues",
        action="store_true",
        help="Display only INVALID and DUPLICATE entries in --verify / --audit-file output.",
    )
    audit_group.add_argument(
        "--fail-on",
        choices=FAIL_ON_MODES,
        default="invalid",
        help="Exit with code 1 policy for --verify / --audit-file (default: 'invalid').",
    )
    audit_group.add_argument(
        "--format",
        choices=FORMAT_MODES,
        default="text",
        help="Output format: 'text' (default), 'json', or 'csv'.",
    )
    audit_group.add_argument(
        "-o",
        "--out",
        default=None,
        help="Write output to file path instead of stdout.",
    )
    return parser


def _write_output(text: str, out_path: Optional[str]) -> None:
    """Write CLI output either to stdout or to a target file."""
    if out_path is None:
        sys.stdout.write(text)
        return
    path = Path(out_path)
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        spec = build_key_spec(
            prefix=args.prefix,
            segments=args.segments,
            segment_length=args.segment_length,
            separator=args.separator,
            alphabet_name=args.alphabet,
            checksum_mode=args.checksum,
            strict=args.strict,
            for_generation=bool(args.generate),
        )

        if args.generate:
            if args.dedupe_out:
                raise ConfigError("--dedupe-out is only valid with --verify or --audit-file.")
            subjects: List[str] = list(args.subject)
            if args.subjects_file:
                subjects.extend(load_subjects_file(args.subjects_file))

            if subjects and args.count is not None:
                raise ConfigError("Cannot combine --count with --subject or --subjects-file.")

            exclude_keys: List[str] = []
            if args.exclude_file:
                exclude_keys = [k for _, k in load_key_entries(args.exclude_file, column=args.column)]

            keys = generate_keys(
                spec,
                count=1 if args.count is None else args.count,
                secret=args.secret,
                seed=args.seed,
                start_index=args.start_index,
                subjects=subjects if subjects else None,
                exclude_keys=exclude_keys,
            )
            rendered = format_generated_output(
                keys,
                spec,
                fmt=args.format,
                keys_only=args.keys_only,
            )
            _write_output(rendered, args.out)
            return 0

        if args.verify is not None:
            if args.verify == ["-"]:
                stdin_text = sys.stdin.read()
                entries = [
                    (idx, line.strip())
                    for idx, line in enumerate(stdin_text.splitlines(), start=1)
                    if line.strip() and not line.strip().startswith("#")
                ]
            else:
                entries = [(idx, key) for idx, key in enumerate(args.verify, start=1)]
            report = audit_key_entries(entries, spec=spec)
        else:
            entries = load_key_entries(args.audit_file, column=args.column)
            report = audit_key_entries(entries, spec=spec)

        dedupe_written: Optional[Tuple[str, int]] = None
        if args.dedupe_out:
            written_count = write_deduped_keys(args.dedupe_out, report["results"], spec)
            dedupe_written = (args.dedupe_out, written_count)

        rendered = format_audit_output(
            report,
            fmt=args.format,
            only_issues=args.only_issues,
            dedupe_written=dedupe_written,
        )
        _write_output(rendered, args.out)
        return 1 if should_fail(report["summary"], args.fail_on) else 0

    except (ConfigError, InputError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
