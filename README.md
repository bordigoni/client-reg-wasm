# WASM Client Registry for Envoy

This project aims to prove possibility to perform
authentication and authorization via a Wasm filter in Envoy using a gRPC service.

Features:
* Sync credentials with a gRPC service (a running module of this project with hard coded credential)
* Perform Basic Auth
* Check client id from JWT token (assuming it is validated beforehand)
* Check API key in query string or any header

## Setup

Rust

`curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh`

Wasm compiler

`rustup target add wasm32-wasi`

## Build the filter
`cd clireg-wasm-filter`

For dev (leaves stack traces when a panic happens)

`cargo build --target wasm32-wasi`


For production

`cargo build --target wasm32-wasi --release`

**warning**: wasm file will be located in `target/wasm32-wasi/**release**/clireg_wasm_filter.wasm` so docker-compose won't work without a change.

## Code : 

see CONTRIBUTING.md

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
*only when there 2 wasm filters in the same filter chain*.
So the gRPC server sends an empty response (no op in wasm filter) just after the actual response to allow envoy to see it.

In the current setting, envoy is not configured in such way.

### protobuf (inc. docs)

You can find the documented protobuf in `proto/` 

## Run (you to build first)

1. Run the gRPC server (in its own shell in clireg-grpc directory) 

   Run you don't run it first but you'll have to wait 60sec before envoy retries.

   `cd clireg-grpc-service`

   `cargo run`

2. Run envoy (in its own shell in clireg-wasm directory)

   you'll need adjustments on Mac as it uses the host network.

   `docker-compose up`

   check out the config (clireg-wasm/envoy.yaml)

## Test

Proxy any httpbin api calls (e.g /headers)

* `curl -vk --resolve apikey-header.ampgw.axway.com:10000:127.0.0.1 "https://apikey-header.ampgw.axway.com:10000/headers" -H 'X-API-KEY: ABCDEF'`
* `curl -vk -u admin:changeme --basic --resolve basic.ampgw.axway.com:10000:127.0.0.1 "https://basic.ampgw.axway.com:10000/headers"`
* `curl -vk --resolve apikey-query.ampgw.axway.com:10000:127.0.0.1 "https://apikey-query.ampgw.axway.com:10000/headers?X-API-KEY=ABCDEF"`
* `curl -vk --resolve jwt.ampgw.axway.com:10000:127.0.0.1 --oauth2-bearer "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjbGllbnRfaWQiOiJiZW5vaXQifQ.wrdsdXeH5tPDmM4alg9jiVNOTXSW1YV_SPCUwKdQPC4" "https://jwt.ampgw.axway.com:10000/headers"`

gRPC test server will change API key and remove basic auth every 10 secs, following call should end up with a 403.
If you don't specify API Key / user&pass you'll end up with a 401.

## Run perf test
* build the filter in production mode or else docker compose won't work 
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
* Generate new certs for *.api.bordigoni.fr
* CI
* gRPC Service 
  * Docker build
  * Config to switch from perf testing to simple.
  * Handle incremental changes, but need to implement a data source abstraction and have one store configured first
* Envoy related
   * use several envoys
* Clean code
  * docs
* Contribute to proxy-wasm test framework in order to run integration tests.
* Wiki to explain various configuration possibilities
