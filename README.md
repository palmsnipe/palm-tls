# PalmTLS

PalmTLS provides TLS 1.1, 1.2, and 1.3 for Palm OS applications. It builds one
installable shared-library PRC for 68K devices and one ARM-enhanced variant for
Palm OS 5 devices.

The repository also includes a small transport-independent HTTP source
component and TLS Tester, a complete installable example. The HTTP component is
compiled directly into applications; it is not another shared library and does
not produce an additional PRC.

## Included

- `library/`: the PalmTLS shared library, public API, ARMlet, and tests
- `components/http/`: directly compiled URL, request, redirect, and response
  parsing code
- `examples/network/`: small compile-checked integration examples
- `apps/tls-tester/`: the installable HTTP/HTTPS and download tester
- `patches/wolfssl/`: Palm-specific changes to the pinned wolfSSL source

## Requirements

- macOS with Xcode Command Line Tools and Homebrew, or Linux with Clang and
  standard Autotools packages
- Node.js
- ImageMagick for generating the TLS Tester icon
- a bootstrapped `palm-toolchain` repository

The optional native ARMlet is compiled with Clang. `ARM_CC` defaults to
`clang`, which uses Apple Clang on macOS and can use upstream LLVM Clang on
Linux. Override it when Clang is installed under a nonstandard name or path:

```sh
make ARM_CC=/path/to/clang
```

By default, the repositories are sibling directories:

```text
projects/
  palm-toolchain/
  palm-tls/
```

Set `PALM_TOOLCHAIN_ROOT` or `PALM_TOOLCHAIN_PREFIX` when using a different
toolchain location.

## Setup

Install the host dependencies:

```sh
brew bundle
```

On Ubuntu 24.04, install the equivalent host packages:

```sh
sudo apt-get update
sudo apt-get install -y \
  autoconf automake clang imagemagick librsvg2-bin libtool nodejs
```

Fetch the pinned wolfSSL revision, apply the Palm patches, and build all
protocol variants:

```sh
make bootstrap
```

Build and validate PalmTLS, the HTTP component, and all examples:

```sh
make check
```

Downloaded source and dependency builds remain inside `.palm-tls/`. Override
that location with `PALM_TLS_STATE`, or only its installed dependency prefix
with `PALM_TLS_DEPS_PREFIX`. Generated library and example outputs remain in
their ignored `build/` directories. `make clean` removes project outputs but
keeps the downloaded and compiled wolfSSL dependency state.

## Installable outputs

Install exactly one PalmTLS variant appropriate for the device:

```text
library/build/palm/PalmTLS68K.prc
library/build/palm/PalmTLSArm.prc
```

PalmTLS also produces smaller `Modern` and `TLS13` profiles. Every variant has
the same Palm database identity, so they cannot coexist on one device. See
`library/README.md` and `library/API.md` for selection and integration details.

Applications compile `components/http/src/http.c` directly when they need the
included HTTP helpers. No separate HTTP PRC is installed or distributed.

## TLS Tester

Build and validate the example application with:

```sh
make tls-tester
```

For an optimized application build, run:

```sh
make -C apps/tls-tester release
```

Create a distributable directory containing all six library PRCs, the public
header and documentation, and the release TLS Tester with:

```sh
scripts/package-artifacts.sh
```

The same packaging command is used by the manually triggered GitHub Actions
workflow. That trusted workflow runs inside a private SDK-enabled toolchain
image and uploads the resulting `dist/` directory as a 30-day build artifact.
It is intentionally not triggered for pull requests. The repository secret
`PALM_TOOLCHAIN_REGISTRY_TOKEN` must contain a dedicated classic GitHub token
with only the `read:packages` scope; do not reuse a general-purpose token.

Install one PalmTLS PRC followed by `TlsTester.prc`. Actual HTTP and HTTPS
requests require a Palm OS device or emulator with working NetLib connectivity.
For 68K testing in CloudpilotEmu, enable its **Overclock** control at 8x or
higher; 512x is recommended for practical public-site TLS handshakes. This
uses CloudpilotEmu's CPU overclock model rather than accelerating the entire
emulated clock.
See `apps/tls-tester/README.md` for usage and trust-profile details.

## License

Copyright (C) 2026 Cyril Morales.

Original material in this repository is free software licensed under the GNU
General Public License, version 3 or (at your option) any later version. See
`LICENSE` for the complete text and `THIRD_PARTY.md` for software retaining
separate copyright notices.

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
source is not vendored into this repository. Palm-specific changes remain as
reviewable patches under `patches/wolfssl/`.
