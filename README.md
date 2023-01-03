# WASM Client Registry for Envoy

## Setup

Rust

`curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh`

Dependencies

`curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh`

Crates (not sure, it is required, but I had issues, so I install those, maybe try without and tell me)

`cargo install wasm-pack` (surely duplicate with the above, but it installed something)

`cargo install wasm-tools`

## Build the filter
`cd clireg-wasm-filter`

`wasm-pack build`

Could not get `cargo build --target wasm32-wasi --release` to work so, but prolly what we want for production performance grades. wasm-pack display stack and lines when a panic occurs.

## Build Client Registry gRPC Service (optional)

`cd clireg-grpc-service`

`cargo build`

### How it works

Once you run the server, it waits for a message (I used a bidi gRPC looks like a better match than unary/stream for envoy) that contains full_sync=true.

Then it delivers a message every ten seconds.
1. api_key ABCDEF (for filter1) + basic admin/change (for filter2)
2. api_key GHIJKL + removal of the above
3. loop forever

There is maybe a bug in Envoy (or misconfiguration or both), messages are delivered 2 by 2. 
So the server sends an empty response along with the actual response to allow envoy to see it.

### protobuf (inc. docs)

You can find the protobuf in `proto/` 

## Run

1. Run the gRPC server (in its own shell in clireg-grpc directory) 

   Run you don't run it first you'll have to wait 60sec before envoy retries.

   `cd clireg-grpc-service`

   `cargo run`

2. Run envoy (in its own shell in clireg-wasm directory)

   you'll need adjustments on Mac as it uses the host network.

   `docker-compose up`

   check out the config (clireg-wasm/envoy.yaml)

## Test

Proxy any httpbin api calls (e.g /headers)

`curl -v  http://localhost:10000/headers -H 'X-API-KEY: ABCDEF' -H 'Authorization: Basic YWRtaW46Y2hhbmdlbWU='`

gRPC test server will chage API key and remove basic auth every 10 secs, following call should end up with a 401.
If you don't specify API Key header you'll end up with a 401.

**Yes I know two authentication for one API is dumb but, it was the simplest way to test several instances of the filter.**

## Code 

I still need to enhance the coding experience, you need to open both directory in separate intellij in order to have it to looked compilable for now. 
It should be feasible.

## TODO

* refactor / cleanup / tests / docs
* explore workspaces to manage two projects in one repo
* try to generate protobuf struct in wasm-filter

  (cannot work for now at it brings tonic in and wasm build fails with too many code that cannot be compiled with the wasm target) 
* understand why messages are consumed 2 by 2
* extends envoy config to have 3 API, no auth, APIKey, Basic + TLS
* allow APIKey in query string
* JWT handling
