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
    "proof_type": "Batch"
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
      "ramp_up_sec": 300,
      "lock_timeout_ms_per_mcycle": 400,
      "timeout_ms_per_mcycle": 900,
      "max_price_per_mcycle": "0.000000085",
      "min_price_per_mcycle": "0.000000005",
      "lock_collateral": "15"
    },
    "aggregation": {
      "ramp_up_sec": 60,
      "lock_timeout_ms_per_mcycle": 3300,
      "timeout_ms_per_mcycle": 6000,
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

## Environment Variables

- `BOUNDLESS_SIGNER_KEY` (required for boundless): private key used to sign transactions
- `BOUNDLESS_RPC_URL` (optional): RPC URL if not set in config
- `SQLITE_DB_PATH` (optional): defaults to `./proof_requests.db`
- `RATE_LIMIT_PER_MINUTE` (optional): defaults to `100`
- `BOUNDLESS_API_KEY` (optional): if set, non-health endpoints require `x-api-key` or `Authorization: Bearer`

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
