# TLS Tester

TLS Tester is an installable Palm OS 3.5+ example that exercises PalmTLS and
the repository's directly compiled HTTP component. It can make HTTP and HTTPS requests, display
connection and handshake timings, download files, and test resumable downloads
using either VFS or a Palm database.

The app is intentionally included as a complete reference rather than a small
code fragment. Its private `DownloadClient` and `DownloadStore` modules show
one way to keep the Palm event loop responsive while driving PalmTLS, parsing
HTTP incrementally, and persisting downloaded data. They are implementation
details of this example, not APIs exported by PalmTLS. See
[DOWNLOADER.md](DOWNLOADER.md) for an architectural overview.

## Build and test

From the repository root, install the host dependencies and bootstrap the
PalmTLS dependency once:

```sh
brew bundle
make bootstrap
```

Then build and validate the app PRC:

```sh
make tls-tester
```

You can also work directly in this directory:

```sh
make test
make release
make benchmark
```

The default build is written to `build/debug/TlsTester.prc`. The repository's
`make check` also runs the HTTP component's host fixtures for fixed-length and
chunked responses, redirects, metadata, resume headers, `416` responses, and
invalid partial responses. These checks need no network connection or emulator.

The build expects `palm-toolchain` and `palm-tls` to be sibling directories.
Set `PALM_TOOLCHAIN_ROOT` or `PALM_TOOLCHAIN_PREFIX` if your layout differs.

## PalmTLS API and HTTP component

TLS Tester checks the protocol, session, cache, resumption, and cooperative-I/O
capability bits it needs. PalmTLS is the only shared-library dependency.

The **Test** action owns its DNS lookup and TCP socket, advances the PalmTLS
handshake cooperatively, sends a `HEAD` request, and reads the result directly.
Plain HTTP uses NetLib directly because no response framing is needed beyond
the diagnostic response buffer.

The **Get** action uses cooperative PalmTLS session open/handshake/read/write
calls and the compiled HTTP component's URL, request, redirect, and parser calls. The
application-owned `DownloadClient` advances this work from the event loop;
`DownloadStore` handles its Palm database and VFS policy. Applications should
use the public header and API guide in `library/`, and treat the tester and HTTP
component source as code that is compiled into each application.

## Install and use

Install these two files in order:

1. One PalmTLS variant:
   `library/build/palm/PalmTLS68K.prc` for 68K/Palm OS 4+, or
   `library/build/palm/PalmTLSArm.prc` for ARM Palm OS 5+
2. `apps/tls-tester/build/debug/TlsTester.prc`

Launch TLS Tester, enter a host name or URL, select HTTP or a supported TLS
version, and tap **Test**. PalmTLS reports only the protocols included in the
installed profile, so the selector adapts to smaller builds. The **Get** button
downloads a URL, while **Files** opens the saved-download catalog.

The certificate verification checkbox is enabled by default. Select the issuer
profile that matches the server being tested. Disabling verification is useful
only for diagnosis and must not be used with credentials or sensitive data.
The included issuer profiles cover the app's Google, Cloudflare, and Let's
Encrypt test cases.

Actual requests require a Palm device or emulator with working NetLib
connectivity. Emulator installation and network configuration are deliberately
outside this example's build process because they vary by emulator and ROM.
Pure 68K public-key operations can take several minutes on period hardware, so
the tester uses a longer operation deadline when the native ARM math path is
not available. In CloudpilotEmu, set the 68K **Overclock** control to at least
8x before making TLS requests. The existing 512x development setting is
recommended for practical public-site tests. Use the overclock control rather
than a whole-emulator speed multiplier so Palm OS timers and peripheral timing
remain synchronized.

## Build profiles

- `debug` builds the normal development PRC.
- `release` produces an optimized release PRC.
- `benchmark` enables the network-free P-256 ECDHE/ECDSA startup workload for
  TLS 1.2 and TLS 1.3.

Normal builds perform fast native bignum, P-256, and SHA-256 known-answer
checks. On supported Palm OS 5 devices, PalmTLS can report native ARM math;
otherwise it uses its 68K path.

## Trust certificates

The app embeds three issuing-CA certificates in DER form. These three small
files are source inputs, not generated build output, and are kept in the
repository so a normal build is offline and reproducible. The other roots,
leaf certificates, PEM copies, and combined bundle used during earlier testing
are not needed and are not included. See `certs/README.md` for provenance,
fingerprints, and expiry dates.

To deliberately download and validate fresh issuer files, run:

```sh
./apps/tls-tester/tools/update-trust-store.sh
make tls-tester
```

The refresh script downloads current leaf certificates only into a temporary
directory to verify that the selected issuer matches the served chain. Review
the three resulting DER changes and update `certs/README.md` before committing
them. A provider can change its chain before an issuer certificate expires.

## Request timing

The result view separates total time into NetLib open, DNS, TCP connect, TLS
engine load, TLS handshake, and HTTP exchange. Run the same host twice when
profiling: the first request includes cold engine loading, while the second can
show cached loading and session resumption behavior.
