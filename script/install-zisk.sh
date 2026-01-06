#!/usr/bin/env bash
set -euo pipefail

log() {
    echo "[zisk-install] $*"
}

warn() {
    echo "[zisk-install] WARN: $*" >&2
}

error() {
    echo "[zisk-install] ERROR: $*" >&2
}

usage() {
    cat <<'USAGE'
Usage: ./script/install-zisk.sh [--rom-setup] [--skip-rom-setup]

Options:
  --rom-setup       Run `cargo-zisk rom-setup` after install
  --skip-rom-setup  Do not run `cargo-zisk rom-setup` (default)
  -h, --help        Show this help message

Environment:
  CUDA_ARCH            Override detected GPU arch (e.g. sm_89)
  ZISKUP_INSTALL_URL   Override ziskup install URL
USAGE
}

detect_cuda_arch() {
    local cap
    if command -v nvidia-smi >/dev/null 2>&1; then
        cap=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -n 1 | tr -d ' ')
        if [ -n "$cap" ] && [[ "$cap" == *.* ]]; then
            local major="${cap%%.*}"
            local minor="${cap##*.}"
            if [ -n "$major" ] && [ -n "$minor" ]; then
                echo "sm_${major}${minor}"
                return 0
            fi
        fi
    fi

    if command -v nvcc >/dev/null 2>&1; then
        echo "sm_89"
        return 0
    fi

    return 1
}

ensure_toolchain() {
    local toolchain="nightly-2024-12-20"
    if ! command -v rustup >/dev/null 2>&1; then
        warn "rustup not found; skipping toolchain install"
        return 0
    fi

    if ! rustup toolchain list | grep -q "$toolchain"; then
        log "Installing Rust toolchain: $toolchain"
        rustup toolchain install "$toolchain"
    else
        log "Rust toolchain already installed: $toolchain"
    fi
}

install_cargo_zisk() {
    if command -v cargo-zisk >/dev/null 2>&1; then
        log "cargo-zisk already installed"
        return 0
    fi

    local url="${ZISKUP_INSTALL_URL:-https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh}"
    log "Installing cargo-zisk from $url"
    curl -fsSL "$url" | bash

    if command -v cargo-zisk >/dev/null 2>&1; then
        log "cargo-zisk installed"
    else
        warn "cargo-zisk not found in PATH. Start a new shell or source your profile."
    fi
}

run_rom_setup() {
    if ! command -v cargo-zisk >/dev/null 2>&1; then
        error "cargo-zisk is not available for rom-setup"
        exit 1
    fi

    log "Running cargo-zisk rom-setup"
    cargo-zisk rom-setup
    log "cargo-zisk rom-setup completed"
}

main() {
    local run_rom_setup=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --rom-setup)
                run_rom_setup=1
                ;;
            --skip-rom-setup)
                run_rom_setup=0
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    if arch=$(detect_cuda_arch); then
        export ZISK_GPU_SUPPORT=1
        if [ -z "${CUDA_ARCH:-}" ]; then
            export CUDA_ARCH="$arch"
        fi
        log "GPU detected. CUDA_ARCH=${CUDA_ARCH}"
    else
        export ZISK_GPU_SUPPORT=${ZISK_GPU_SUPPORT:-0}
        if [ -n "${CUDA_ARCH:-}" ]; then
            warn "CUDA_ARCH is set but no GPU was detected"
        else
            log "No GPU detected. Using CPU mode"
        fi
    fi

    ensure_toolchain
    install_cargo_zisk

    if [ "$run_rom_setup" -eq 1 ]; then
        run_rom_setup
    fi

    log "Zisk install complete"
}

main "$@"
