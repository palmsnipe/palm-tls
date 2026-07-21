# PalmHTTP

PalmHTTP is a small Palm OS shared library layered above an application's
transport. It provides HTTP/HTTPS URL parsing, redirect resolution, resumable
GET request construction, filename extraction, and incremental HTTP/1.1 body
framing. It does not open sockets, choose TLS versions, or own downloaded data.

Install `PalmHTTP.prc`, load creator `PHTP`, call `PalmHttpLibOpen`, and use the
streaming parser with a caller-owned `PalmHttpParser` and body callback. This
keeps PalmTLS independently reusable and lets applications direct decoded body
chunks to VFS, a record database, an XML parser, or another sink.

Typical use is:

```c
PalmHttpUrl url;
PalmHttpParser parser;

PalmHttpLibParseUrl(httpRefNum, "https://example.com/file.bin", true, &url);
PalmHttpLibParserInit(httpRefNum, &parser, resumeOffset, SaveChunk, contextP);

/* Feed each plaintext chunk returned by PalmTLS or NetLib. */
PalmHttpLibParserFeed(httpRefNum, &parser, bytesP, byteCount);
PalmHttpLibParserFinish(httpRefNum, &parser);
```

The parser object is caller-owned and contains no library-global session state,
so several applications can open the library and each can maintain its own
HTTP operation. A single parser must only be advanced by one task at a time.

See [API.md](API.md) for the function contracts, supported framing, fixed
limits, redirects, and range-response rules. The
[network examples](../../examples/network/README.md) are compiled against the
published Palm headers.

Build and validate with:

```sh
make -C libs/palm-http test
make -C examples/network test
```
