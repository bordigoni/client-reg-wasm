# WASM Client Registry for Envoy

## Setup

Rust

`curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh`

Dependencies

`curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh`

Creates (not sure it is required, but I had issues so I install those)

`cargo install wasm-pack` (surely duplicate with the above, but it installed something)
`cargo install wasm-tools`

## Build

`wasm-pack build`

Couln't get `cargo build --target wasm32-wasi --release` to work so, but prolly what we want for production performance grades. wasm-pack display stack and lines when a panic occurs.

## Run

`docker-compose up`

## Test

Proxy any httpbin api calls (e.g /headers)

`curl -v  http://localhost:10000/headers -H 'X-API-KEY: ABCDEF' -H 'Authorization: Basic YWRtaW46Y2hhbmdlbWU='`

Change API key or remove basic auth to witness errors.

Yes I know two authentication is dumb but that is the simplest way to test several instances of my wasm filters.
