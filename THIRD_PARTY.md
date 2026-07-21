# Third-party software

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
