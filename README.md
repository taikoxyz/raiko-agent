# Raiko Agent

An HTTP service that receives proof requests from Raiko and dispatches them to prover backends.
Boundless is implemented today; Zisk and Brevis (pico) are placeholders.

## Features

- **Async proof requests**: `/proof`, `/status/:request_id`, `/requests`, `DELETE /requests`, `/stats`
- **Multi-prover routing**: `prover_type` = `boundless`, `zisk`, `brevis_pico`
- **ELF upload workflow**: `/upload-image/{prover_type}/{batch|aggregation}` (per-prover in-memory cache)
- **Image inventory**: `/images`
- **SQLite persistence**: request tracking and cleanup on startup

## Build

```bash
cargo build --release
```

## Run

```bash
export BOUNDLESS_SIGNER_KEY=0x...
./target/release/raiko-agent \
  --address 0.0.0.0 \
  --port 9999 \
  --config-file config/boundless_config_base_deployment.json

curl http://localhost:9999/health

# If BOUNDLESS_API_KEY is set, include it in requests:
curl -H "x-api-key: $BOUNDLESS_API_KEY" http://localhost:9999/requests
```

OpenAPI docs are exposed at `/docs`, `/scalar`, and `/openapi.json`.

For Kubernetes deployment and config guidance, see `K8S_DEPLOYMENT.md`.

## API Quickstart

Submit a proof request:

```bash
curl -X POST http://localhost:9999/proof \
  -H "Content-Type: application/json" \
  -d '{
    "prover_type": "boundless",
    "input": [1, 2, 3, 4, 5],
    "output": [1, 2, 3, 4, 5],
    "proof_type": "batch"
  }'
```

Upload an ELF image:

```bash
curl -X POST http://localhost:9999/upload-image/boundless/batch \
  -H "Content-Type: application/octet-stream" \
  --data-binary @path/to/guest.elf
```

Check image inventory:

```bash
curl http://localhost:9999/images
```

Note: `zisk` and `brevis_pico` proof submission returns `501 Not Implemented`, but ELF images
can be staged for them.

## Configuration

The service requires a Boundless JSON config via `--config-file` (no merge). Examples:
- `config/boundless_config_docker.json`
- `config/boundless_config_base_deployment.json`

```json
{
  "deployment": {
    "deployment_type": "Base",
    "overrides": { "order_stream_url": "https://base-mainnet.boundless.network" }
  },
  "offer_params": {
    "batch": {
      "ramp_up_start_sec": 30,
      "ramp_up_period_blocks": 15,
      "lock_timeout_ms_per_mcycle": 90,
      "timeout_ms_per_mcycle": 215,
      "max_price_per_mcycle": "0.000000085",
      "min_price_per_mcycle": "0.000000005",
      "lock_collateral": "15"
    },
    "aggregation": {
      "ramp_up_start_sec": 30,
      "ramp_up_period_blocks": 15,
      "lock_timeout_ms_per_mcycle": 1500,
      "timeout_ms_per_mcycle": 4500,
      "max_price_per_mcycle": "0.00000006",
      "min_price_per_mcycle": "0.000000006",
      "lock_collateral": "15"
    }
  },
  "rpc_url": "https://base-rpc.publicnode.com"
}
```

`deployment` and `rpc_url` are optional; `offer_params.batch` and `offer_params.aggregation`
are required.

### Offer Params Guidance

- `ramp_up_start_sec`: delay (seconds) after request creation before bidding starts.
- `ramp_up_period_blocks`: ramp-up duration in **blocks** (Base uses ~2s/block). Ensure `ramp_up_period_blocks * block_time_sec <= (lock_timeout_ms_per_mcycle * mcycles / 1000)` so ramp-up finishes before the lock timeout elapses.
- `lock_timeout_ms_per_mcycle`: lock timeout in **milliseconds per million cycles**; total lock timeout in seconds is `lock_timeout_ms_per_mcycle * mcycles / 1000`. The primary prover must fulfill by this time.
- `timeout_ms_per_mcycle`: request expiry in **milliseconds per million cycles**; total expiry time in seconds is `timeout_ms_per_mcycle * mcycles / 1000`. This total expiry must be greater than the total lock timeout (i.e., use `timeout_ms_per_mcycle` > `lock_timeout_ms_per_mcycle` for the same workload).
- `max_price_per_mcycle` / `min_price_per_mcycle`: per‑mcycle price bounds; min defaults to 0 if omitted.
- `lock_collateral`: fixed ZKC amount (explicitly configured; not derived from price).

Example targets used in configs (assuming ~7B cycles for batch, ~200M for aggregation):
- Batch: lock ~10 min, timeout ~25 min → 90 / 215 ms_per_mcycle
- Aggregation: lock ~5 min, timeout ~15 min → 1500 / 4500 ms_per_mcycle

## Environment Variables

- `BOUNDLESS_SIGNER_KEY` (required for boundless): private key used to sign transactions (can be overridden with `--signer-key`)
- `BOUNDLESS_RPC_URL` (optional): RPC URL if not set in config
- `SQLITE_DB_PATH` (optional): defaults to `./proof_requests.db`
- `RATE_LIMIT_PER_MINUTE` (optional): defaults to `0` (disabled)
- `BOUNDLESS_API_KEY` (optional): if set, non-health endpoints require `x-api-key` or `Authorization: Bearer`
- `ALLOW_UNAUTHENTICATED` (optional): set to `true` to allow destructive endpoints without an API key

## Docker

Build and run locally:

```bash
docker build -t raiko-agent:local .
docker run --rm -p 9999:9999 -e BOUNDLESS_SIGNER_KEY=0x... raiko-agent:local
```

Build helper (mirrors `raiko/script/publish-image.sh` conventions):

```bash
DOCKER_REPOSITORY=us-docker.pkg.dev/evmchain/images ./script/publish-image.sh <tag>
# The script will ask if you want to push; say y/Y to push to the registry.
```

Override image name (default: `raiko-agent`):

```bash
IMAGE_NAME=raiko-agent-custom ./script/publish-image.sh <tag>
```

## Development

```bash
cargo test
```
