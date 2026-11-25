# Query-shaped upstream packets observed on a PS5 Pro

## Observation (2026-11-24)

NanoDNS 0.4 was running on a PS5 Pro, with ProsperoStore 1.000.120 as
the client. The client used NanoDNS on `127.0.0.1:53`. The original payload's
SHA-256 was
`dcb845f3570771275b22b37534bf924a7f8ae219fb91ef00c6bccab85d1c2420`.

The catalog initially loaded, but subsequent requests to GitHub hosts timed
out with curl 28. Eventually catalog requests also timed out. Changing the
first upstream from AdGuard to Cloudflare and restarting NanoDNS helped
temporarily, but the failure returned. This was not specific to one provider.

A diagnostic payload on the console sent an ordinary UDP A query for
`release-assets.githubusercontent.com`, with RD set, to NanoDNS and directly
to public resolvers. In the failing state:

| Destination | Sent bytes | Received bytes | First 16 received bytes |
| --- | ---: | ---: | --- |
| NanoDNS (`127.0.0.1`) | 54 | 54 | `1234010000010000000000000e72656c` |
| AdGuard (`94.140.14.14`) | 54 | 118 | `1234818000010004000000000e72656c` |
| Cloudflare (`1.1.1.1`) | 54 | 118 | `1234818000010004000000000e72656c` |

The local packet had the query's transaction ID, question prefix and length,
and **QR=0**. Both direct replies had **QR=1** and four answers. The diagnostic
recorded the header/prefix, not a full packet capture, so it does not establish
byte-for-byte identity of the entire packet or where it originated.

NanoDNS logged the local packet as a successful upstream result:

```text
[nanodns] response via=1.1.1.1 ... qname=release-assets.githubusercontent.com qtype=A(1) rcode=NOERROR(0) answers=0 authority=0 additional=0
```

The forwarding loop checked packet length and transaction ID, but not QR.
The client therefore received a query-shaped packet instead of a DNS response.

## Patch and validation

The console patch rejected packets with QR=0 and closed the connected upstream
UDP socket after each successful response, so the next lookup used a fresh
socket. No DNS provider or blocklist changes accompanied that patch.

After deployment, five rounds of six queries passed: five public hostnames
(`prosperostore.net`, `github.com`, `api.github.com`, `raw.githubusercontent.com`,
`release-assets.githubusercontent.com`) and one locally blocked hostname
(`ps5.np.playstation.net`). All 30 responses had QR=1 and answers; the blocked
hostname continued to return `0.0.0.0`. A second 30-query sequence during PR
preparation also passed, after the successful application update.

ProsperoStore then downloaded and installed Crux2 successfully:

```text
[STORE] curl status=200 bytes=39113320 error=
[STORE] job id=PPSA99249 operation=update ok=1 version=01.023.000 error= files=281 unpack_ms=1697 write_ms=925 sync_ms=265 worker=1
```

`tests/upstream-regression.py` exercises the actual production forwarding
function with scripted socket operations. It checks that a query-shaped packet
is rejected, fallback reaches a valid second upstream, all-invalid upstreams
fail, successful requests leave no socket for reuse, and existing rejection of
short packets and mismatched IDs is preserved. It fails against unmodified 0.4
on the QR assertion and passes with the patch under ASan/UBSan.

## Limits and tradeoff

This is evidence from one PS5 Pro. It does not establish the mechanism that
caused the query-shaped packets. Restarting NanoDNS and changing providers
helped temporarily before the patch; neither by itself was a lasting fix.

QR validation is a directly supported correctness fix. Opening a fresh socket
for every lookup is an empirically tested mitigation, not a proven explanation
of the underlying failure. The two changes have not been isolated in separate
console A/B runs. Socket refresh adds socket/connect/close calls per successful
upstream query. PS4 behavior, long-duration operation, and throughput under
heavy DNS load remain unverified. The configured timeout budget is unchanged.
