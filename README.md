# RISC0 Boundless Agent

An HTTP service for generating RISC0 Boundless proofs and submitting them to the Boundless Market.

## Features

- **Async proof requests**: `/proof`, `/status/:request_id`, `/requests`
- **ELF upload workflow**: `/upload-image/{batch|aggregation}` (images kept in-memory and refreshed via TTL)
- **SQLite persistence**: request tracking and cleanup on startup

## Build

```bash
cargo build --release
```

## Run

```bash
export BOUNDLESS_SIGNER_KEY=0x...
./target/release/boundless-agent \
  --address 0.0.0.0 \
  --port 9999 \
  --config-file config/boundless_config_docker.json

curl http://localhost:9999/health

# If BOUNDLESS_API_KEY is set, include it in requests:
curl -H "x-api-key: $BOUNDLESS_API_KEY" http://localhost:9999/requests
```

OpenAPI docs are exposed at `/docs`, `/scalar`, and `/openapi.json`.

For Kubernetes deployment and config guidance, see `K8S_DEPLOYMENT.md`.

## Configuration

The service can load a JSON config via `--config-file` and merges it with defaults. Examples:
- `config/boundless_config_docker.json`
- `config/boundless_config_base_deployment.json`

```json
{
  "deployment": { "deployment_type": "Base", "overrides": { "order_stream_url": "https://base-mainnet.boundless.network" } },
  "offer_params": { "batch": { "max_price_per_mcycle": "0.00000002" } },
  "rpc_url": "https://base-rpc.publicnode.com"
}
```

## Environment Variables

- `BOUNDLESS_SIGNER_KEY` (required): private key used to sign transactions
- `SQLITE_DB_PATH` (optional): defaults to `./boundless_requests.db`
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
IMAGE_NAME=boundless-agent ./script/publish-image.sh <tag>
```

## Development

```bash
cargo test
```
