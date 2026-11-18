# HTTP component

This directory contains the small transport-independent HTTP/1.1 component
used by PalmTLS examples. It is ordinary source code compiled directly into an
application. It is not an installed Palm shared library, does not produce a
PRC, and has no runtime version or lifecycle API.

Include `include/http.h` and compile `src/http.c` with the application. The
component provides:

- HTTP and HTTPS URL parsing;
- absolute and relative redirect resolution;
- GET, resumable Range, and fixed-length POST header construction;
- safe filename derivation;
- incremental response parsing with fixed-length, chunked, and
  connection-delimited bodies;
- ETag, Last-Modified, Content-Range, filename, and MIME metadata.

It deliberately does not own NetLib, sockets, TLS sessions, storage, redirect
policy, or event-loop scheduling. Applications supply plaintext response bytes
and a body callback.

```c
HttpUrl url;
HttpParser parser;

HttpParseUrl("https://example.com/file.bin", true, &url);
HttpParserInit(&parser, resumeOffset, SaveChunk, contextP);
HttpParserFeed(&parser, bytesP, byteCount);
HttpParserFinish(&parser);
```

The parser removes response headers and chunk framing before invoking the body
callback. It consumes headers one line at a time, so the total header block is
not capped. Oversized headers that determine framing, decoding, or connection
reuse return `httpHeadersTooLarge`. Long optional fields can be skipped.
Identity encoding is the
default. Applications that decompress gzip themselves
can set `parser.acceptGzip = true` after initialization and check `parser.gzip`
in the body callback. The parser removes HTTP framing and passes the encoded
body to that callback. Redirect and resume validation remain application policy.

Applications using long enclosure URLs can set `HTTP_PATH_CAPACITY` and
`HTTP_LOCATION_CAPACITY` when compiling both the component and its caller.
`HttpBuildGetRequest` checks that the base request fits before writing the
buffer and includes the port in `Host` for non-default HTTP or HTTPS ports.

`HttpBuildGetRequestEx` can set the user agent and advertise gzip. Set the
response parser's `acceptGzip` flag independently if the caller can decode it.
`HttpBuildPostRequest` returns the header length. `HttpBuildPostRequestEx`
also accepts a keep-alive option. Send the body as a separate binary buffer
with the exact declared length.

Run the host fixtures and Palm cross-compilation check with:

```sh
make -C components/http test
```
