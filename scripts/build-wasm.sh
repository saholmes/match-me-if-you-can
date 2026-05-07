#!/usr/bin/env bash
# Build the browser STARK prover (mmiyc-wasm) and post-process with
# wasm-bindgen so frontend/index.html can `import init` from the
# resulting ES module.  Output lands in frontend/wasm/.
#
# Toolchain:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.99
#
# The wasm-bindgen-cli version must match the wasm-bindgen crate
# version pinned in crates/mmiyc-wasm/Cargo.toml — version drift
# produces an "unknown ABI version" error at instantiate time.
set -euo pipefail

cd "$(dirname "$0")/.."

cargo build --release -p mmiyc-wasm --target wasm32-unknown-unknown

wasm-bindgen \
    --target web \
    --out-dir frontend/wasm \
    --no-typescript \
    target/wasm32-unknown-unknown/release/mmiyc_wasm.wasm

ls -lh frontend/wasm/
