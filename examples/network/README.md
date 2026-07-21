# Palm network examples

These examples are deliberately small integration units rather than separate
installable applications. `make test` compiles all of them with the Palm ABI,
so API changes that break the documentation are caught by the build.

- `library_lifecycle.c`: safely find/load, open, version-check, close, and
  unload PalmTLS and PalmHTTP.
- `cooperative_tls.c`: advance one connected TLS request without owning the
  Palm event loop.
- `http_stream.c`: construct a resumable GET and feed decrypted HTTP bytes to
  the streaming parser.

Compile them with:

```sh
make -C examples/network test
```

These files are intended to be copied or adapted inside an application rather
than installed directly.
