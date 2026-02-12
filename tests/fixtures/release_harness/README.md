# Release harness fixture

This directory contains the **default fixture manifest** for the release smoke harness.

## What you need to provide

- **ELF/program** (choose one):
  - **Docker image extraction (recommended)**: set `upload.docker_elf.image` and `upload.docker_elf.internal_path`
    - Example: `us-docker.pkg.dev/evmchain/images/raiko-zk:1.14.2`
    - Internal path: `/opt/raiko/provers/risc0/elf/boundless-batch.bin`
  - **Local file**: set `upload.elf_path` to a local path (e.g. `tests/fixtures/release_harness/boundless_batch.bin`)
- **Signer key**: set `BOUNDLESS_SIGNER_KEY` in `fixture.json` (or override via env).
- **RPC / storage configuration**: set via the agent config file and env vars.

## Input fixtures

`/proof` expects `input` as **bytes**. The harness supports:
- binary input files (sent as-is)
- JSON input files:
  - `[1,2,3]` → treated as bytes
  - `{...}` or other JSON → bincode(serde_json::Value)

You can override with `proof.input_encoding`:
- `auto` (default)
- `raw`
- `json_bytes_array`
- `bincode_bytes`

## Output fixtures

`/proof` also includes an `output` byte array. For the Boundless batch program, we commonly
provide a **len-prefixed hash**:

`output_bytes = u32_le(len(hash_bytes)) || hash_bytes`

If your output fixture is JSON and contains a top-level `"hash": "0x..."`, the harness will
auto-encode it this way. You can force behavior with `proof.output_encoding`:
- `auto` (default)
- `raw`
- `json_bytes_array`
- `json_bytes_array`
- `len_prefixed_hash`

## How to run

Build release binary first:

```bash
cargo build --release
```

Run harness (spawns agent by default):

```bash
cargo run --bin release_harness -- --fixture tests/fixtures/release_harness/fixture.json
```

If you already have an agent running, set `"base_url": "http://127.0.0.1:9999"` and `"agent.spawn": false`.

If you want to avoid spending funds while validating fixtures, set `"agent.evaluation_only": true`
(this passes `--evaluation-only` to the spawned `raiko-agent`).

