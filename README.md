# nanoDNS for PS4/PS5

Minimal PS4/PS5 payload DNS proxy that:

- listens on a configurable local IPv4 address on port `53`
- applies local IPv4 overrides for domains matching shell-style masks
- forwards all other DNS queries to upstream resolvers from `/data/nanodns/nanodns.ini`
- stores runtime files under `/data/nanodns`
- writes DNS queries and responses to a log file
- can additionally mirror logs to `stdout`/`klog` when `debug=1`
- supports an exceptions block to bypass local overrides for selected domains
- can bind the listening socket to a specific local IPv4 address

Upstream resolvers are tried in the order listed in the config. The payload
stops on the first valid response within the configured timeout budget.

## Build

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

PS4 build:

```sh
export PS4_PAYLOAD_SDK=/opt/ps4-payload-sdk
make -f Makefile.ps4
```

## Deploy

```sh
make test PS5_HOST=<ps5-ip-or-hostname>
```

PS4 deploy:

```sh
make -f Makefile.ps4 test PS4_HOST=<ps4-ip-or-hostname>
```

## Config

At startup the payload uses the directory `/data/nanodns`.
The config file path is `/data/nanodns/nanodns.ini`.
If the file does not exist, it creates one with defaults:

```ini
[general]
log=/data/nanodns/nanodns.log
debug=0
bind=127.0.0.1

[upstream]
server=1.1.1.1
server=8.8.8.8
server=77.77.88.88
timeout_ms=1500

[overrides]
*.playstation.com=0.0.0.0
*.playstation.com.*=0.0.0.0
playstation.com=0.0.0.0
*.playstation.net=0.0.0.0
*.playstation.net.*=0.0.0.0
*.psndl.net=0.0.0.0
playstation.net=0.0.0.0
psndl.net=0.0.0.0
# *.example.com=192.168.0.10
# exact.host.local=10.0.0.42

[exceptions]
feature.api.playstation.com
*.stun.playstation.net
stun.*.playstation.net
ena.net.playstation.net
post.net.playstation.net
gst.prod.dl.playstation.net
# auth.api.playstation.net
# *.allowed.playstation.net
```

Override masks use shell-style wildcard matching with `*`, `?`, bracket classes
like `[abc]`, ranges like `[a-z]`, and negated classes like `[!0-9]`, for example:

- `*.example.com`
- `api??.test.local`
- `exact.host.local`

`debug=0` disables mirrored output to console and `klog`, but the file specified by
`log=` still receives all requests and responses. The log file is overwritten on
each startup.

`bind=` sets the local IPv4 address used by the listening socket. The default is `127.0.0.1`.
Use `bind=0.0.0.0` to listen on all local IPv4 interfaces.

Entries in `[upstream]` are attempted in order. `timeout_ms` is the total time budget
for trying the configured upstream servers for a single query.

Entries in `[exceptions]` are also shell-style masks, one per line. If a query
matches an exception, it is forwarded to upstream DNS and bypasses all local
override rules.
