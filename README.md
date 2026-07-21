# Palm Network

Reusable HTTP and TLS shared libraries for Palm OS applications.

## Included

- `PalmHTTP`, a Palm shared library for HTTP transfers through NetLib
- `PalmTLS`, a Palm shared library providing TLS 1.1, 1.2, and 1.3 profiles
- 68K and ARM-enhanced PalmTLS builds
- a pinned, Palm-specific wolfSSL build with its compatibility patches
- TLS Tester, an installable example application for exercising both libraries

Application projects use the public headers under `libs/*/include` and install
the generated library PRCs alongside their application PRC.

## Requirements

- macOS with Xcode Command Line Tools
- Homebrew
- Node.js
- ImageMagick (used to generate the TLS Tester icon)
- a bootstrapped `palm-toolchain` repository

By default, `palm-toolchain` and `palm-network` are sibling directories:

```text
projects/
  palm-toolchain/
  palm-network/
```

Override that convention with `PALM_TOOLCHAIN_ROOT` or
`PALM_TOOLCHAIN_PREFIX` when necessary.

## Setup

Install the small set of host dependencies:

```sh
brew bundle
```

Build the pinned wolfSSL variants into `.network/prefix`:

```sh
make bootstrap
```

Build and validate both Palm shared libraries:

```sh
make check
```

Generated dependency state remains inside the repository under `.network/`,
and generated library outputs remain under each library's ignored `build/`
directory. Run `make clean` to remove the library and example outputs. Remove
`.network/` manually only when a completely fresh wolfSSL rebuild is needed.

## Outputs

The principal installable files are:

```text
libs/palm-http/build/palm/PalmHTTP.prc
libs/palm-tls/build/palm/PalmTLS68K.prc
libs/palm-tls/build/palm/PalmTLSArm.prc
examples/tls-tester/build/debug/TlsTester.prc
```

PalmTLS also produces smaller `Modern` and `TLS13` profiles. See the library
READMEs and API documents for selection and integration details.

## TLS Tester example

Build and validate the installable example with:

```sh
make tls-tester
```

Install one PalmTLS PRC, then `PalmHTTP.prc`, then `TlsTester.prc` on a Palm OS
3.5 or newer device or emulator. The build and host-side parser tests run
offline; making actual HTTP and HTTPS requests requires working Palm NetLib
connectivity. See `examples/tls-tester/README.md` for usage and profile details.

## License

Copyright (C) 2026 Cyril Morales.

Original material in this repository is free software licensed under the GNU
General Public License, version 3 or (at your option) any later version. You may
use, study, modify, and redistribute it under those terms. See `LICENSE` for
the complete GPLv3 text and `THIRD_PARTY.md` for software retaining separate
copyright notices.

PalmTLS incorporates wolfSSL. Distributions containing PalmTLS and wolfSSL
must comply with GPLv3 unless the distributor has obtained a suitable
commercial license from wolfSSL Inc. Preserve upstream notices and provide the
complete corresponding source when distributing PRC binaries.

For a binary release, publish the repository source, the exact wolfSSL source
identified by `config/sources.lock`, the Palm-specific patches, and the scripts
needed to reproduce the binaries. Applications distributed in combination
with PalmTLS must also use GPLv3-compatible terms unless covered by a separate
wolfSSL commercial license or exception.

## External source

wolfSSL is fetched at the exact commit recorded in `config/sources.lock`; its
source is not vendored into this repository. Palm-specific changes are kept as
reviewable patches under `patches/wolfssl`.
