# Copilot instructions for temurin-vdr-generator

Purpose: Give AI coding agents just enough context to be productive and safe in this repo.

## Big picture
- Goal: produce a CycloneDX VDR (JSON) by combining OJVG advisories with NIST NVD data.
- Flow:
  1) `ojvg_download.py` scrapes OJVG and writes `data/openjvg_summary.json` (intermediate).
  2) `ojvg_convert.py` converts that JSON to CycloneDX vulnerabilities, enriches from NIST, builds a BOM, validates, and writes `data/vdr.json`.

## Key modules and roles
- `cvereporter/fetch_dates.py`: parse OJVG advisories index HTML → list of ISO dates (YYYY-MM-DD).
- `cvereporter/fetch_vulnerabilities.py`: fetch/parse one OJVG advisory page → list of dicts and `Vulnerability` objects; intersects affected majors from the table with versions parsed from header text; fixed PURL `pkg:github/openjdk/jdk`; version ranges encoded as `vers:generic/<v1>|<v2>|...`.
- `cvereporter/nist_enhance.py`: fetch NIST JSON (cached under `data/nist_<CVE>.json`) and add description + CVSSv3.1 ratings to vulnerabilities. Optional API key via `NIST_NVD_TOKEN`.
- `cvereporter/report.py`: build base BOM (Temurin metadata), serialize JSON (v1.4 writer) and validate against CycloneDX v1.6 strict schema.

## Developer workflow
- Install: `python3 -m pip install -r requirements.txt`
- Test: `python3 -m pytest -q` (offline fixtures in `tests/data/`)
- Format: `python3 -m black <files>`
- End-to-end (network):
  - Ensure `data/` exists.
  - `python3 ojvg_download.py` → writes `data/openjvg_summary.json`.
  - Optionally export `NIST_NVD_TOKEN` for higher rate limits.
  - `python3 ojvg_convert.py` → writes `data/vdr.json`.

## Data contracts
- Intermediate JSON: `{ "data": [ [ {row...}, ... ], ... ] }` (nested lists). Use `ojvg_convert.flatten_file` to flatten into `list[dict]`.
- OJVG dict keys: `id`, `url`, `date`, `component`, `affected` (e.g., `7u361`, `8u352`), `ojvg_url`, `ojvg_score` (float or NaN).
- Vulnerability affects: PURL `pkg:github/openjdk/jdk`; version ranges via `BomTargetVersionRange(range="vers:generic/7u361|8u352")`.

## Parsing specifics and pitfalls
- OJVG table class is `risk-matrix`; affected majors marked by `•`. Intersection with header-listed versions is heuristic—maintain behavior and tests if changing.
- Rows with CVE `None` are skipped. Missing tables return `None`/`[]`; callers must handle gracefully.
- NIST version extraction exists but is disabled (`extract_versions_from_nist = False`). Don’t enable without updating tests and consumers.

## Testing patterns
- See `tests/test_pipeline.py` for expectations (IDs, PURL, version ranges, NIST fields). Use fixtures under `tests/data/`; avoid live HTTP in tests.
- Prefer pure functions that accept strings/objects; keep network I/O isolated for easy testing.

## Safe change guidelines
- Preserve intermediate dict keys and CycloneDX encoding to avoid breaking `ojvg_convert.py` and consumers of `data/vdr.json`.
- Add new sources by normalizing into the same dict shape, then reuse `dict_to_vulns` and `nist_enhance.enhance`.
- If adding deps, pin versions in `requirements.txt` consistently with current pins.

## Open questions for maintainers
- Target Python version for CI (project uses modern typing; tests run on 3.10+)?
- Any downstream consumers depending on specific fields in `data/vdr.json` beyond CycloneDX defaults?
