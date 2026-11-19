# license-serial-checksum-generator-cli-lite

Zero-dependency Python 3.9+ CLI to generate, batch-export, deduplicate, and verify Crockford-alphabet software license keys with Luhn-mod-32/36 checksums.

---

## Features

- **Zero external dependencies**: Pure Python 3.9+ standard library (`argparse`, `csv`, `hashlib`, `hmac`, `json`, `secrets`). No virtual environment or third-party packages required.
- **Unambiguous Crockford-32 & Base-36 alphabets**:
  - `crockford32` (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) eliminates visually confusing `I`, `L`, `O`, and `U` characters.
  - Non-strict verification automatically normalizes lowercase input and common human transcription typos (`I`/`L` -> `1`, `O` -> `0`), while `--strict` enforces exact canonical uppercase characters.
  - `base36` (`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ`) supported with `luhn36` or `none`.
- **Luhn-mod-32 and Luhn-mod-36 checksums**: Built-in check-digit generation and verification catches single-character typos and adjacent transpositions offline before keys hit your database.
- **Two generation engines (`--generate`)**:
  - **CSPRNG (`secrets`)**: Default cryptographically random unique key batches with automatic in-batch deduplication and optional `--exclude-file` collision avoidance.
  - **Deterministic (`HMAC-SHA256`)**: Reproducible keys derived via counter-mode HMAC-SHA256 using `--secret`, `--seed`, `--start-index`, or per-order/per-customer `--subject` / `--subjects-file`.
- **Bulk validation & deduplication (`--verify` & `--audit-file`)**:
  - Validate single keys, `stdin` streams (`-`), line-delimited `.txt` files, or multi-column `.csv` files (auto-detecting `,`/`;` delimiters and standard key column names or `--column`).
  - Detect canonical duplicates even when transcribed with lowercase or Crockford aliases (`o`/`0`, `l`/`1`), export clean unique keys via `--dedupe-out`, and integrate into CI with `--fail-on {invalid,duplicate,any,none}`.
- **Flexible output formats**: Aligned ASCII tables (`--format text`), structured `--format json`, RFC-4180 `--format csv`, or raw `--keys-only` lines, with optional `--out` file export.

---

## Quick Start

### 1. Generate CSPRNG or Deterministic License Keys

```bash
# Generate 5 cryptographically random Crockford-32 keys with PRO prefix
python serial_keygen.py --generate --count 5 --prefix PRO

# Generate deterministic keys using HMAC-SHA256
python serial_keygen.py --generate --count 4 --prefix PRO --secret "demo-secret-2026" --seed "v1"
```

Example output:

```text
Generated 4 key(s) | Mode: hmac-sha256 | Alphabet: crockford32 | Checksum: luhn32 | Prefix: PRO

# | Key                     | Mode        | Checksum
--+-------------------------+-------------+---------
1 | PRO-0V9J-0N7H-8152-CZ4H | hmac-sha256 | luhn32
2 | PRO-EZ2W-BHM1-S99C-KHKV | hmac-sha256 | luhn32
3 | PRO-0388-1XCV-9GKV-139R | hmac-sha256 | luhn32
4 | PRO-QJ9H-589X-QWJJ-01KH | hmac-sha256 | luhn32
```

### 2. Derive Deterministic Keys per Order / Subject & Export CSV

```bash
python serial_keygen.py --generate --secret "demo-secret-2026" --seed "v1" --subject "order-1042" --subject "order-1043" --prefix SAAS --format csv
```

```csv
index,key,prefix,mode,alphabet,checksum,subject
1,SAAS-36VT-97N7-D116-3M3N,SAAS,hmac-sha256,crockford32,luhn32,order-1042
2,SAAS-TX07-QEME-Y6S5-4GX5,SAAS,hmac-sha256,crockford32,luhn32,order-1043
```

### 3. Verify Individual Keys or Audit & Deduplicate Bulk Lists

```bash
# Verify individual key(s)
python serial_keygen.py --verify PRO-0V9J-0N7H-8152-CZ4H --prefix PRO

# Audit a TXT or CSV key batch, detect canonical duplicates, and export clean unique keys
python serial_keygen.py --audit-file batch_keys.txt --prefix PRO --dedupe-out clean_keys.csv
```

Example audit output:

```text
Key Audit Summary | Total: 4 | Unique Valid: 2 | Duplicates: 1 | Invalid: 1 | Normalized: 1 | Status: FAIL

Line | Status    | Raw Key                 | Canonical Key           | Code             | Details
-----+-----------+-------------------------+-------------------------+------------------+------------------------------------------------
1    | VALID     | PRO-0V9J-0N7H-8152-CZ4H | PRO-0V9J-0N7H-8152-CZ4H | -                | OK
2    | VALID     | PRO-EZ2W-BHM1-S99C-KHKV | PRO-EZ2W-BHM1-S99C-KHKV | -                | OK
3    | DUPLICATE | pro-ov9j-on7h-8l52-cz4h | PRO-0V9J-0N7H-8152-CZ4H | DUPLICATE_KEY    | Duplicate canonical key (first seen at line 1).
4    | INVALID   | PRO-EZ2W-BHM1-S99C-KHK0 | -                       | INVALID_CHECKSUM | Failed luhn32 checksum verification.
```

### 4. Base-36 / Luhn-mod-36, Custom Geometry, and Collision Exclusion

```bash
# Generate 20 Base-36 keys with Luhn-mod-36 checksum and 5x5 geometry
python serial_keygen.py --generate --count 20 --prefix APP --segments 5 --segment-length 5 --alphabet base36 --checksum luhn36 --format json

# Generate 100 new keys guaranteed not to collide with previously issued keys
python serial_keygen.py --generate --count 100 --prefix PRO --exclude-file issued_keys.csv --format csv --out new_batch.csv

# Audit only invalid/duplicate rows in CI and exit 1 on any issue
python serial_keygen.py --audit-file orders.csv --column license_key --prefix PRO --only-issues --fail-on any
```

---

## CLI Options & Exit Codes

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--generate` | `false` | Generate CSPRNG (`secrets`) or deterministic (`HMAC-SHA256`) license keys |
| `--verify KEY [KEY ...]` | `—` | Verify one or more keys (or `-` to read lines from `stdin`) |
| `--audit-file PATH` | `—` | Audit and deduplicate a bulk `.txt` or `.csv` file (`-` for `stdin`) |
| `--prefix` | `""` | Optional uppercase product/tier prefix (e.g. `PRO`, `SAAS`) |
| `--segments` | `4` (gen) | Number of key body segments |
| `--segment-length` | `4` (gen) | Characters per body segment |
| `--separator` | `"-"` | Segment separator (pass `""` for contiguous keys) |
| `--alphabet` | `crockford32` | Body alphabet: `crockford32` or `base36` |
| `--checksum` | `auto` | Checksum mode: `auto`, `luhn32`, `luhn36`, or `none` |
| `--strict` | `false` | Require exact uppercase characters and disallow `I/L->1`, `O->0` aliases |
| `-n`, `--count` | `1` | Number of keys to generate |
| `--secret` | `—` | HMAC-SHA256 secret for deterministic generation |
| `--seed` | `license-v1` | Domain namespace seed used with `--secret` |
| `--start-index` | `1` | Starting index for deterministic batch generation |
| `--subject` | `[]` | Repeatable subject/order ID for deterministic derivation |
| `--subjects-file` | `—` | File containing one subject ID per line |
| `--exclude-file` | `—` | Existing TXT/CSV key list to exclude from CSPRNG generation |
| `--keys-only` | `false` | Emit raw generated keys one per line in `--format text` |
| `--column` | auto | CSV column name or 0-based index for `--audit-file` / `--exclude-file` |
| `--dedupe-out` | `—` | Write unique valid canonical keys to a `.txt` or `.csv` file |
| `--only-issues` | `false` | Output only `INVALID` and `DUPLICATE` records |
| `--fail-on` | `invalid` | Exit `1` policy for `--verify` / `--audit-file`: `invalid`, `duplicate`, `any`, or `none` |
| `--format` | `text` | Output format: `text`, `json`, or `csv` |
| `-o`, `--out` | stdout | Write output to a file path |

**Exit Codes**: `0` = success within `--fail-on` policy, `1` = audit/verify triggered `--fail-on` policy, `2` = invalid arguments, configuration error, or unreadable file.

---

## Lite CLI vs Full Telegram License Key Vault & Delivery Bot + Web Admin Pro

This open-source Lite CLI handles offline key generation, checksum validation, and CSV/TXT batch deduplication. When you need a **self-hosted license vault that imports key stock, delivers keys automatically in Telegram, tracks buyers, revokes/replaces keys, and exposes a browser admin dashboard**, compare both editions below:

| Capability | Lite CLI (Free MIT) | Full Telegram License Key Vault & Delivery Bot + Web Admin Pro |
| :--- | :--- | :--- |
| Crockford-32 / Base-36 key & Luhn-mod-32/36 checksum generation | Yes | Yes (plus vault batch ingestion) |
| Deterministic HMAC-SHA256 & CSPRNG key derivation | Yes | Yes |
| Bulk CSV/TXT validation & canonical deduplication | Yes | Persistent SQLite vault with atomic stock reservation |
| Automated Telegram customer key delivery & order lookup | — | Yes (instant delivery + buyer self-service history) |
| Low-stock Telegram alerts & anti-duplicate key guard | — | Yes |
| Browser Web Admin dashboard (products, batches, orders, revocation) | — | Yes |
| Exportable sales/inventory reports & one-click deployment scripts | — | Yes |

- **Get the Pro Edition on FunPay:** https://funpay.com/lots/offer?id=82603936

---

## Running Tests

```bash
py -m unittest discover -s tests -v
```

---

## License

MIT License — see [LICENSE](LICENSE).
