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

There is maybe a bug in Envoy (or an odd behaviour), messages are delivered 2 by 2 
*only when there 2 wasm filter in the same filter chain, supposedly on the same VM*.
So the gRPC server sends an empty response (no op in wasm filter) just after the actual response to allow envoy to see it.

### protobuf (inc. docs)

You can find the documented protobuf in `proto/` 

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

## Run perf test
* gRPC service: see above (use of data.rs/many_creds() function so that no credentials removal occurs and on 403 can happen, and get up to a 1 000 000 creds.
* envoy & backend (nighthawk sending 10 bytes): `docker-compose --compatibility -f docker-compose-perf.yaml up`
* client (add those hosts to /etc/hosts `hey` does not have a dynamic local DNS cache like cURL with --resolve) :
  * single calls:
    * `curl -kv "https://apikey.ampgw.axway.com:8443/" -H 'X-API-KEY: ABCDEF'`
    * `curl -kv "https://basic.ampgw.axway.com:8443/" -H 'Authorization: Basic YWRtaW46Y2hhbmdlbWU='`
    * `curl -kv "https://noauth.ampgw.axway.com:8443/"`
  * bulk load (install hey: https://github.com/rakyll/hey)
    * `hey -c <users> -q <qps/user> -z 1m -cpus 4 -H 'X-API-KEY: ABCDEF' -m GET -host apikey.ampgw.axway.com "https://apikey.ampgw.axway.com:8443/"`
    * `hey -c <users> -q <qps/user> -z 1m -cpus 4 -H 'Authorization: Basic YWRtaW46Y2hhbmdlbWU=' -m GET -host basic.ampgw.axway.com "https://basic.ampgw.axway.com:8443/"`
    * `hey -c <users> -q <qps/user> -z 1m -cpus 4 -m GET -host noauth.ampgw.axway.com "https://noauth.ampgw.axway.com:8443/"`

## Next steps

* Features / deps related
  * JWT handling
  * try to generate protobuf struct in wasm-filter

    (cannot work for now at it brings tonic in and wasm build fails with too many code that cannot be compiled with the wasm target)
  * allow APIKey in query string
  * use grpc code gen compatible with wasm
  * remove hard coded values (if any)
* Envoy related
   * use several envoys
* Clean code
  * tests / docs
  * integration tests with proxy-wasm tests
  * adopt a more "functional" style for results and options
  * Config as JSON (protobuf Struct)

