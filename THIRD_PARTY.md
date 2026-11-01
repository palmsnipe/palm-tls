# Third-party software

## P-256 inversion schedule

The addition-chain schedule in `library/arm/multiply.c:FeInverse` follows
`p256Inverse` in the Go standard library, copyright 2015 The Go Authors,
under its BSD-3-Clause license. The notice and license are retained in
`library/arm/p256-inverse.LICENSE` and must accompany binary distributions
(the artifact packager includes it as `library/p256-inverse.LICENSE`).
The reference revision is
[`be35de22f18a3c16e24a20490ec1fc316ea12b04`](https://go.googlesource.com/go/+/be35de22f18a3c16e24a20490ec1fc316ea12b04/src/crypto/internal/fips140/nistec/p256_asm.go).

## wolfSSL

The bootstrap fetches wolfSSL from `https://github.com/wolfSSL/wolfssl` at the
commit pinned in `config/sources.lock` and applies the patches in
`patches/wolfssl`.

wolfSSL is offered under the GNU General Public License version 3 and under
separate commercial licensing. The pinned source files state GPL version 3 or,
at the recipient's option, a later version. The GPLv2 exceptions listed by
wolfSSL do not include this project.

The Palm-specific wolfSSL patches are modifications of GPL-covered wolfSSL
code and are distributed under GPL-3.0-or-later. Preserve wolfSSL's copyright
and licensing notices. Consult wolfSSL Inc. before distributing PalmTLS under
terms other than GPLv3-compatible terms.

## Palm OS SDK and build tools

This repository does not distribute the Palm OS SDK or compiler toolchain.
Those are supplied by the separate `palm-toolchain` repository and retain
their respective licenses.
