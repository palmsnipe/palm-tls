# PalmHTTP API

PalmHTTP is a transport-independent HTTP/1.1 helper. Include
`include/palm_http.h`, load creator `PALM_HTTP_LIB_CREATOR` as a system library,
and balance `PalmHttpLibOpen` with `PalmHttpLibClose`.

`PalmHttpLibSleep` and `PalmHttpLibWake` satisfy the standard Palm shared
library lifecycle. They do not suspend or resume an HTTP parser; parser objects
remain caller-owned memory.

## Discovery

`PalmHttpLibGetApiVersion` returns the installed ABI version.
`PalmHttpLibGetCapabilities` reports URL, redirect, chunked, range, and
streaming support. Accept newer API versions and check the capability bits used
by the application.

## URL operations

`PalmHttpLibParseUrl` accepts an HTTP/HTTPS URL or a host/path value. The
`defaultSecure` argument selects the scheme when none is present. The output
contains `secure`, the explicit/default port, a lower-level connection host,
and a request path. Failure means malformed or too large input.

`PalmHttpLibResolveRedirect` resolves an absolute HTTP/HTTPS URL, absolute path,
or relative path against a base `PalmHttpUrl`. Scheme-relative (`//host/path`)
locations are not supported. Redirect policy and loop/count detection
belong to the application.

`PalmHttpLibFilenameFromUrl` derives a bounded safe filename from the URL path.
After parsing a response, prefer the parser's Content-Disposition filename when
present.

## Request construction

`PalmHttpLibBuildRequest` writes an HTTP/1.1 GET request into the caller's
buffer and returns its byte length, or zero if it does not fit. It adds `Host`,
`Accept-Encoding: identity`, and either `Connection: keep-alive` or
`Connection: close` according to the caller's `keepAlive` argument.

When `resumeOffset` is nonzero it adds `Range: bytes=<offset>-`. A nonempty
`validatorP` also adds `If-Range`; use a previously stored ETag when available,
otherwise Last-Modified. The caller must not append its own bytes unless a
`206 Content-Range` begins exactly at the requested offset.

## Streaming parser

The caller owns a `PalmHttpParser`. Initialize it with
`PalmHttpLibParserInit`, an expected resume offset, a body callback, and context.
Feed plaintext bytes in any split—including one byte at a time—with
`PalmHttpLibParserFeed`. When the transport reaches clean EOF, call
`PalmHttpLibParserFinish`.

Once `connectionComplete` is true, `connectionReusable` indicates that the
response had unambiguous HTTP/1.1 framing and did not request
`Connection: close`. Only then may another request use the same transport.

The body callback receives decoded entity bytes only: status line, headers,
chunk sizes, CRLF delimiters, and trailers are removed. Callback memory is
temporary. Return zero after consuming the whole chunk; any nonzero result
stops parsing as `palmHttpSinkFailed`.

After headers complete, the parser exposes status, redirect location, ETag,
Last-Modified, Content-Disposition filename, MIME type, body length/range
metadata, and framing flags. Do not trust body metadata before the relevant
header flags are set.

Supported response framing:

- fixed `Content-Length`;
- HTTP/1.1 chunked transfer encoding, including split chunk lines and trailers;
- connection-delimited body, completed by `ParserFinish` at clean EOF.

Only identity content encoding is accepted. gzip, deflate, and other content
codings return `palmHttpUnsupportedEncoding`. Informational/multiple response
blocks, upgrades, pipelining, uploads, and arbitrary request methods are not
supported.

## Redirects and range responses

Statuses 301, 302, 303, 307, and 308 require a Location header and set
`parser.redirect`. The parser reports the target but never follows it.

A `206` is malformed unless it has a usable Content-Range matching the parser's
resume offset. A `416` must contain an unsatisfied Content-Range. The application
must compare total length and its durable local state before declaring a 416
already complete.

## Limits and concurrency

The public structure fixes the ABI and storage costs: 2,048 bytes of response
headers, 128 bytes for host, 256 for path and redirect location, 128 for ETag,
64 each for date, filename, and MIME type, and 18 for an in-progress chunk-size
line. Oversized or malformed input fails closed.

Parser state is caller-owned, so different applications or operations may keep
independent parsers. Do not advance the same parser concurrently or recursively
from its body callback.

## Examples

- `examples/network/http_stream.c`: URL, request, parser, and sink lifecycle
- `examples/tls-tester/src/download_client.c`: cooperative application integration
- `examples/tls-tester/tests/http_download_test.c`: framing and resume fixtures
