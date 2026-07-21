# HTTP component

This directory contains the small transport-independent HTTP/1.1 component
used by PalmTLS examples. It is ordinary source code compiled directly into an
application. It is not an installed Palm shared library, does not produce a
PRC, and has no runtime version or lifecycle API.

Include `include/http.h` and compile `src/http.c` with the application. The
component provides:

- HTTP and HTTPS URL parsing;
- absolute and relative redirect resolution;
- GET and resumable Range request construction;
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
callback. Only identity content encoding is supported. Redirect and resume
validation decisions remain the application's responsibility.

Run the host fixtures and Palm cross-compilation check with:

```sh
make -C components/http test
```
