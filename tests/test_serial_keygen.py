#!/usr/bin/env python3
"""Offline unit and CLI integration tests for serial_keygen.py."""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import serial_keygen as sk  # noqa: E402


class TestLuhnAndAlphabets(unittest.TestCase):
    def test_luhn_mod_32_check_digit_and_all_single_substitutions(self) -> None:
        payload = "9F4K7M2QX8WRT5V"
        check = sk.luhn_mod_n_check_char(payload, sk.CROCKFORD32_ALPHABET)
        full = payload + check
        self.assertTrue(sk.verify_luhn_mod_n(full, sk.CROCKFORD32_ALPHABET))

        # Exhaustively test every single-character substitution across every position
        for pos in range(len(full)):
            original = full[pos]
            for candidate in sk.CROCKFORD32_ALPHABET:
                if candidate == original:
                    continue
                mutated = full[:pos] + candidate + full[pos + 1 :]
                self.assertFalse(
                    sk.verify_luhn_mod_n(mutated, sk.CROCKFORD32_ALPHABET),
                    msg=f"Failed to detect substitution at pos={pos}: {original}->{candidate}",
                )

    def test_luhn_mod_36_check_digit_and_transposition_detection(self) -> None:
        payload = "APP2026Z9KLM4Q1"
        check = sk.luhn_mod_n_check_char(payload, sk.BASE36_ALPHABET)
        full = payload + check
        self.assertTrue(sk.verify_luhn_mod_n(full, sk.BASE36_ALPHABET))

        # Adjacent distinct transposition must be caught
        swapped = list(full)
        self.assertNotEqual(swapped[2], swapped[3])
        swapped[2], swapped[3] = swapped[3], swapped[2]
        self.assertFalse(sk.verify_luhn_mod_n("".join(swapped), sk.BASE36_ALPHABET))

    def test_crockford_alphabet_excludes_ambiguous_letters(self) -> None:
        self.assertEqual(len(sk.CROCKFORD32_ALPHABET), 32)
        for forbidden in ("I", "L", "O", "U"):
            self.assertNotIn(forbidden, sk.CROCKFORD32_ALPHABET)

        spec = sk.build_key_spec(for_generation=True)
        keys = sk.generate_keys(spec, count=100)
        for item in keys:
            for forbidden in ("I", "L", "O", "U"):
                self.assertNotIn(forbidden, item.key)

    def test_crockford_normalization_lowercase_and_aliases(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        # Deterministic key containing 0 and 1 so we can test O->0 and I/L->1 aliases
        keys = sk.generate_keys(spec, count=20, secret="norm-test", seed="v1")
        target = next((k.key for k in keys if "0" in k.key[4:] and "1" in k.key[4:]), None)
        if target is None:
            # Synthesize a guaranteed valid key with explicit 0 and 1
            payload = "0123456789ABCDE"
            body = payload + sk.luhn_mod_n_check_char(payload, sk.CROCKFORD32_ALPHABET)
            target = sk.format_body(body, segments=4, segment_length=4, separator="-", prefix="PRO")

        body_mutated = target[4:].replace("0", "o").replace("1", "i").lower()
        aliased = "pro-" + body_mutated
        res = sk.verify_key(aliased, spec=spec)
        self.assertTrue(res.valid)
        self.assertTrue(res.normalized)
        self.assertEqual(res.canonical_key, target)

        # Also test 'L' -> '1' and verify 'U' is strictly rejected
        aliased_l = "PRO-" + target[4:].replace("1", "L")
        res_l = sk.verify_key(aliased_l, spec=spec)
        self.assertTrue(res_l.valid)
        self.assertEqual(res_l.canonical_key, target)

        with_u = target[:-2] + "U" + target[-1]
        res_u = sk.verify_key(with_u, spec=spec)
        self.assertFalse(res_u.valid)
        self.assertEqual(res_u.error_code, "INVALID_CHARACTER")

    def test_strict_mode_rejects_lowercase_and_aliases(self) -> None:
        payload = "0123456789ABCDE"
        body = payload + sk.luhn_mod_n_check_char(payload, sk.CROCKFORD32_ALPHABET)
        canonical = sk.format_body(body, segments=4, segment_length=4, separator="-", prefix="PRO")

        strict_spec = sk.build_key_spec(prefix="PRO", strict=True)
        self.assertTrue(sk.verify_key(canonical, spec=strict_spec).valid)

        # Lowercase prefix rejected in strict mode
        lower_prefix = "pro-" + canonical[4:]
        res_lower = sk.verify_key(lower_prefix, spec=strict_spec)
        self.assertFalse(res_lower.valid)
        self.assertEqual(res_lower.error_code, "PREFIX_MISMATCH")

        # Alias O->0 rejected in strict mode
        aliased = "PRO-" + canonical[4:].replace("0", "O")
        res_alias = sk.verify_key(aliased, spec=strict_spec)
        self.assertFalse(res_alias.valid)
        self.assertEqual(res_alias.error_code, "INVALID_CHARACTER")


class TestKeyGeneration(unittest.TestCase):
    def test_secrets_generation_uniqueness_and_custom_geometry(self) -> None:
        spec = sk.build_key_spec(
            prefix="saas",
            segments=5,
            segment_length=5,
            separator=":",
            for_generation=True,
        )
        generated = sk.generate_keys(spec, count=150)
        self.assertEqual(len(generated), 150)
        raw_keys = [g.key for g in generated]
        self.assertEqual(len(set(raw_keys)), 150)

        verify_spec = sk.build_key_spec(
            prefix="SAAS",
            segments=5,
            segment_length=5,
            separator=":",
        )
        for key in raw_keys:
            self.assertTrue(key.startswith("SAAS:"))
            self.assertEqual(len(key.split(":")), 6)
            res = sk.verify_key(key, spec=verify_spec)
            self.assertTrue(res.valid, msg=f"Generated key failed verify: {key}")

    def test_secrets_generation_respects_exclude_file_in_tiny_keyspace(self) -> None:
        # 1 segment of length 2 with luhn32 => 32 distinct valid keys total
        spec = sk.build_key_spec(segments=1, segment_length=2, for_generation=True)
        all_32 = [
            ch + sk.luhn_mod_n_check_char(ch, sk.CROCKFORD32_ALPHABET)
            for ch in sk.CROCKFORD32_ALPHABET
        ]
        excluded = all_32[:30]
        expected_remaining = set(all_32[30:])

        generated = sk.generate_keys(spec, count=2, exclude_keys=excluded)
        got = {g.key for g in generated}
        self.assertEqual(got, expected_remaining)

    def test_keyspace_exhaustion_raises_config_error(self) -> None:
        spec = sk.build_key_spec(segments=1, segment_length=2, for_generation=True)
        with self.assertRaises(sk.ConfigError):
            sk.generate_keys(spec, count=33)

    def test_hmac_deterministic_batch_reproducibility(self) -> None:
        spec = sk.build_key_spec(prefix="VIP", for_generation=True)
        batch_a = sk.generate_keys(spec, count=5, secret="s3cr3t", seed="prod-2026", start_index=10)
        batch_b = sk.generate_keys(spec, count=5, secret="s3cr3t", seed="prod-2026", start_index=10)
        self.assertEqual([k.key for k in batch_a], [k.key for k in batch_b])

        # Verify each generated key passes verification
        for item in batch_a:
            self.assertEqual(item.mode, "hmac-sha256")
            self.assertTrue(sk.verify_key(item.key, spec=spec).valid)

        # Different secret, seed, or start_index yields distinct keys
        diff_secret = sk.generate_keys(spec, count=5, secret="other", seed="prod-2026", start_index=10)
        diff_seed = sk.generate_keys(spec, count=5, secret="s3cr3t", seed="prod-2027", start_index=10)
        diff_index = sk.generate_keys(spec, count=5, secret="s3cr3t", seed="prod-2026", start_index=11)
        self.assertNotEqual([k.key for k in batch_a], [k.key for k in diff_secret])
        self.assertNotEqual([k.key for k in batch_a], [k.key for k in diff_seed])
        self.assertNotEqual(batch_a[0].key, diff_index[0].key)
        self.assertEqual(batch_a[1].key, diff_index[0].key)

    def test_hmac_large_payload_counter_mode_and_subjects(self) -> None:
        # 12 segments x 5 chars = 60 chars (> 32 bytes SHA-256 block), triggers ctr >= 1
        spec = sk.build_key_spec(
            prefix="ENT",
            segments=12,
            segment_length=5,
            for_generation=True,
        )
        subjects = ["tenant-alpha", "tenant-beta", "order-9981"]
        keys = sk.generate_keys(spec, secret="master-hmac", seed="enterprise", subjects=subjects)
        self.assertEqual(len(keys), 3)
        self.assertEqual([k.subject for k in keys], subjects)
        for item in keys:
            self.assertEqual(len(item.key), 4 + 12 * 5 + 11)
            self.assertTrue(sk.verify_key(item.key, spec=spec).valid)

    def test_checksum_modes_and_alphabet_pairing_validation(self) -> None:
        spec_36 = sk.build_key_spec(checksum_mode="luhn36", for_generation=True)
        self.assertEqual(spec_36.alphabet_name, "base36")
        self.assertEqual(spec_36.checksum_mode, "luhn36")
        key_36 = sk.generate_keys(spec_36, count=1)[0].key
        self.assertTrue(sk.verify_key(key_36, spec=spec_36).valid)

        spec_none = sk.build_key_spec(alphabet_name="crockford32", checksum_mode="none", for_generation=True)
        key_none = sk.generate_keys(spec_none, count=1)[0].key
        self.assertTrue(sk.verify_key(key_none, spec=spec_none).valid)

        with self.assertRaises(sk.ConfigError):
            sk.build_key_spec(alphabet_name="base36", checksum_mode="luhn32")
        with self.assertRaises(sk.ConfigError):
            sk.build_key_spec(alphabet_name="crockford32", checksum_mode="luhn36")

    def test_no_separator_mode_generation_and_verification(self) -> None:
        spec = sk.build_key_spec(prefix="APP", segments=3, segment_length=4, separator="", for_generation=True)
        key = sk.generate_keys(spec, count=1, secret="nosep")[0].key
        self.assertNotIn("-", key)
        self.assertTrue(key.startswith("APP"))
        self.assertEqual(len(key), 15)
        self.assertTrue(sk.verify_key(key, spec=spec).valid)

    def test_prefix_and_separator_validation(self) -> None:
        with self.assertRaises(sk.ConfigError):
            sk.build_key_spec(prefix="PRO-1", separator="-")
        with self.assertRaises(sk.ConfigError):
            sk.build_key_spec(prefix="PRO$TIER")
        with self.assertRaises(sk.ConfigError):
            sk.build_key_spec(separator="A")
        with self.assertRaises(sk.ConfigError):
            sk.build_key_spec(segments=1, segment_length=1, checksum_mode="luhn32", for_generation=True)


class TestVerificationAndAuditing(unittest.TestCase):
    def test_verify_error_codes(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", segments=4, segment_length=4)
        valid_key = sk.generate_keys(spec, count=1, secret="err-test")[0].key

        self.assertEqual(sk.verify_key("   ", spec=spec).error_code, "EMPTY_KEY")
        self.assertEqual(sk.verify_key("FREE-" + valid_key[4:], spec=spec).error_code, "PREFIX_MISMATCH")
        self.assertEqual(sk.verify_key("PRO-", spec=spec).error_code, "EMPTY_BODY")
        self.assertEqual(sk.verify_key("PRO-AAAA--BBBB-CCCC", spec=spec).error_code, "MALFORMED_SEGMENTS")
        self.assertEqual(sk.verify_key("PRO-AAAA-BBBB-CCCC", spec=spec).error_code, "SEGMENT_COUNT_MISMATCH")
        self.assertEqual(sk.verify_key("PRO-AAAAA-BBBB-CCCC-DDDD", spec=spec).error_code, "SEGMENT_LENGTH_MISMATCH")

        # Inconsistent segment lengths even when segments/segment_length are unspecified
        loose_spec = sk.build_key_spec(prefix="PRO")
        self.assertEqual(sk.verify_key("PRO-AAA-BBBB-CCCC-DDDD", spec=loose_spec).error_code, "SEGMENT_LENGTH_MISMATCH")

        # Too short body
        self.assertEqual(sk.verify_key("PRO-A", spec=loose_spec).error_code, "TOO_SHORT")

    def test_audit_txt_with_comments_duplicates_and_canonical_collision(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        payload = "0123456789ABCDE"
        body = payload + sk.luhn_mod_n_check_char(payload, sk.CROCKFORD32_ALPHABET)
        key1 = sk.format_body(body, segments=4, segment_length=4, separator="-", prefix="PRO")
        key2 = sk.generate_keys(spec, count=1, secret="k2")[0].key
        key1_alias = "pro-" + key1[4:].replace("0", "o").replace("1", "l").lower()
        tampered = key2[:-1] + ("0" if key2[-1] != "0" else "1")

        with tempfile.TemporaryDirectory() as tmpdir:
            txt_path = Path(tmpdir) / "keys.txt"
            txt_path.write_text(
                "\n".join(
                    [
                        "# Batch header comment",
                        "",
                        key1,
                        key2,
                        key1_alias,
                        tampered,
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            entries = sk.load_key_entries(str(txt_path))
            report = sk.audit_key_entries(entries, spec=spec)
            summary = report["summary"]
            self.assertEqual(summary["total_entries"], 4)
            self.assertEqual(summary["unique_valid"], 2)
            self.assertEqual(summary["duplicates"], 1)
            self.assertEqual(summary["invalid"], 1)
            self.assertEqual(summary["normalized_count"], 1)

            dup_row = report["results"][2]
            self.assertEqual(dup_row.status, "DUPLICATE")
            self.assertEqual(dup_row.line, 5)
            self.assertEqual(dup_row.first_seen_line, 3)
            self.assertEqual(dup_row.canonical_key, key1)

    def test_audit_csv_auto_header_semicolon_and_single_column_headerless(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        keys = [k.key for k in sk.generate_keys(spec, count=3, secret="csv-test")]

        with tempfile.TemporaryDirectory() as tmpdir:
            # Multi-column semicolon CSV with recognized 'license_key' column
            csv_multi = Path(tmpdir) / "orders.csv"
            csv_multi.write_text(
                "\n".join(
                    [
                        "order_id;license_key;tier",
                        f"101;{keys[0]};pro",
                        f"102;{keys[1]};pro",
                        f"103;{keys[0]};pro",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            entries = sk.load_key_entries(str(csv_multi))
            report = sk.audit_key_entries(entries, spec=spec)
            self.assertEqual(report["summary"]["unique_valid"], 2)
            self.assertEqual(report["summary"]["duplicates"], 1)

            # Single-column CSV without header
            csv_single = Path(tmpdir) / "bare.csv"
            csv_single.write_text("\n".join(keys) + "\n", encoding="utf-8")
            bare_entries = sk.load_key_entries(str(csv_single))
            self.assertEqual(len(bare_entries), 3)
            self.assertEqual(bare_entries[0], (1, keys[0]))

    def test_audit_csv_explicit_column_and_errors(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        keys = [k.key for k in sk.generate_keys(spec, count=2, secret="col-test")]

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_custom = Path(tmpdir) / "custom.csv"
            csv_custom.write_text(
                "\n".join(
                    [
                        "customer,voucher_code",
                        f"acme,{keys[0]}",
                        f"globex,{keys[1]}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            # Without --column, multi-column CSV without standard header raises InputError
            with self.assertRaises(sk.InputError):
                sk.load_key_entries(str(csv_custom))

            # With --column by name
            entries_by_name = sk.load_key_entries(str(csv_custom), column="voucher_code")
            self.assertEqual([k for _, k in entries_by_name], keys)

            # Missing column raises InputError
            with self.assertRaises(sk.InputError):
                sk.load_key_entries(str(csv_custom), column="missing_col")

            # Headerless multi-column CSV selected by 0-based index
            csv_no_hdr = Path(tmpdir) / "nohdr.csv"
            csv_no_hdr.write_text(f"row1,{keys[0]}\nrow2,{keys[1]}\n", encoding="utf-8")
            entries_by_idx = sk.load_key_entries(str(csv_no_hdr), column="1")
            self.assertEqual([k for _, k in entries_by_idx], keys)

    def test_dedupe_out_writes_clean_txt_and_csv(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        keys = [k.key for k in sk.generate_keys(spec, count=2, secret="dedupe-test")]
        bad_key = keys[0][:-1] + ("0" if keys[0][-1] != "0" else "1")

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "raw.txt"
            src.write_text("\n".join([keys[0], keys[0].lower(), bad_key, keys[1]]) + "\n", encoding="utf-8")
            out_txt = Path(tmpdir) / "clean.txt"
            out_csv = Path(tmpdir) / "clean.csv"

            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc = sk.main(
                    [
                        "--audit-file",
                        str(src),
                        "--prefix",
                        "PRO",
                        "--dedupe-out",
                        str(out_txt),
                        "--fail-on",
                        "none",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertEqual(out_txt.read_text(encoding="utf-8").splitlines(), keys)

            with redirect_stdout(io.StringIO()):
                rc_csv = sk.main(
                    [
                        "--audit-file",
                        str(src),
                        "--prefix",
                        "PRO",
                        "--dedupe-out",
                        str(out_csv),
                        "--format",
                        "json",
                        "--fail-on",
                        "none",
                    ]
                )
            self.assertEqual(rc_csv, 0)
            with out_csv.open("r", encoding="utf-8", newline="") as fh:
                rows = list(csv.reader(fh))
            self.assertEqual(rows[0], ["index", "key", "prefix", "alphabet", "checksum"])
            self.assertEqual([r[1] for r in rows[1:]], keys)

    def test_only_issues_filter_across_formats(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        valid_key = sk.generate_keys(spec, count=1, secret="filter-test")[0].key
        entries = [(1, valid_key), (2, valid_key), (3, "PRO-BAD-KEY")]
        report = sk.audit_key_entries(entries, spec=spec)

        json_out = json.loads(sk.format_audit_output(report, fmt="json", only_issues=True))
        self.assertEqual(json_out["summary"]["unique_valid"], 1)
        self.assertEqual([r["status"] for r in json_out["results"]], ["DUPLICATE", "INVALID"])

        csv_out = sk.format_audit_output(report, fmt="csv", only_issues=True)
        csv_rows = list(csv.reader(io.StringIO(csv_out)))
        self.assertEqual(len(csv_rows), 3)  # header + 2 issues

        text_out = sk.format_audit_output(report, fmt="text", only_issues=True)
        self.assertIn("DUPLICATE", text_out)
        self.assertIn("INVALID", text_out)


class TestCLIIntegration(unittest.TestCase):
    def test_cli_generate_formats_keys_only_and_out_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = Path(tmpdir) / "keys.json"
            rc = sk.main(
                [
                    "--generate",
                    "--count",
                    "4",
                    "--prefix",
                    "LITE",
                    "--secret",
                    "cli-secret",
                    "--format",
                    "json",
                    "--out",
                    str(out_json),
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["count"], 4)
            self.assertEqual(len(payload["keys"]), 4)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc_plain = sk.main(
                    [
                        "--generate",
                        "--count",
                        "3",
                        "--prefix",
                        "LITE",
                        "--keys-only",
                    ]
                )
            self.assertEqual(rc_plain, 0)
            lines = buf.getvalue().strip().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertTrue(all(line.startswith("LITE-") for line in lines))

    def test_cli_subjects_file_and_csv_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sub_file = Path(tmpdir) / "subjects.txt"
            sub_file.write_text("# orders\norder-1\norder-2\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = sk.main(
                    [
                        "--generate",
                        "--secret",
                        "sub-secret",
                        "--subjects-file",
                        str(sub_file),
                        "--prefix",
                        "SAAS",
                        "--format",
                        "csv",
                    ]
                )
            self.assertEqual(rc, 0)
            rows = list(csv.reader(io.StringIO(buf.getvalue())))
            self.assertEqual(rows[0], ["index", "key", "prefix", "mode", "alphabet", "checksum", "subject"])
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[1][6], "order-1")
            self.assertEqual(rows[2][6], "order-2")

    def test_cli_verify_and_audit_via_stdin_subprocess(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        keys = [k.key for k in sk.generate_keys(spec, count=2, secret="stdin-test")]
        stdin_payload = "\n".join(keys) + "\n"

        proc_verify = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "serial_keygen.py"), "--verify", "-", "--prefix", "PRO", "--format", "json"],
            input=stdin_payload,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_verify.returncode, 0, msg=proc_verify.stderr)
        data = json.loads(proc_verify.stdout)
        self.assertEqual(data["summary"]["unique_valid"], 2)

        proc_audit = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "serial_keygen.py"), "--audit-file", "-", "--prefix", "PRO", "--format", "json"],
            input=f"key\n{keys[0]}\n{keys[0]}\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_audit.returncode, 0, msg=proc_audit.stderr)
        audit_data = json.loads(proc_audit.stdout)
        self.assertEqual(audit_data["summary"]["unique_valid"], 1)
        self.assertEqual(audit_data["summary"]["duplicates"], 1)

    def test_cli_fail_on_policies_and_error_exit_codes(self) -> None:
        spec = sk.build_key_spec(prefix="PRO", for_generation=True)
        valid_key = sk.generate_keys(spec, count=1, secret="fail-policy")[0].key
        bad_key = valid_key[:-1] + ("0" if valid_key[-1] != "0" else "1")

        # Duplicate only: fails under duplicate/any, passes under invalid/none
        with redirect_stdout(io.StringIO()):
            self.assertEqual(sk.main(["--verify", valid_key, valid_key, "--prefix", "PRO", "--fail-on", "invalid"]), 0)
            self.assertEqual(sk.main(["--verify", valid_key, valid_key, "--prefix", "PRO", "--fail-on", "duplicate"]), 1)
            self.assertEqual(sk.main(["--verify", valid_key, valid_key, "--prefix", "PRO", "--fail-on", "any"]), 1)

        # Invalid key: fails under invalid/any, passes under duplicate/none
        with redirect_stdout(io.StringIO()):
            self.assertEqual(sk.main(["--verify", bad_key, "--prefix", "PRO", "--fail-on", "invalid"]), 1)
            self.assertEqual(sk.main(["--verify", bad_key, "--prefix", "PRO", "--fail-on", "duplicate"]), 0)
            self.assertEqual(sk.main(["--verify", bad_key, "--prefix", "PRO", "--fail-on", "none"]), 0)

        # Missing file or invalid config exits with code 2
        with redirect_stderr(io.StringIO()):
            self.assertEqual(sk.main(["--audit-file", "does_not_exist_12345.txt"]), 2)
            self.assertEqual(sk.main(["--generate", "--count", "0"]), 2)
            self.assertEqual(sk.main(["--generate", "--secret", ""]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
