# Releasing PalmTLS

Build a candidate before creating a version tag. Verify that candidate in the
emulator, then promote the same PRCs and binary ZIP. The publishing command
never rebuilds a binary, moves a tag, overwrites an existing asset, or modifies
an already-published release. ROM-dependent checks run locally using the
user-supplied emulator and session; CI runs the independent CPU-model tests.

## 1. Prepare a release commit

Start from the intended branch with the latest upstream changes and tags:

```sh
git pull --ff-only
git fetch origin --tags
python3 scripts/release.py prepare 0.1.5
```

`prepare` requires a clean working tree, advances both `library/app.mk` and
`apps/tls-tester/app.mk`, and creates `docs/releases/0.1.5.md`. Replace its TODO
with user-visible changes and installation guidance. Do not invent performance
numbers: measured results and corresponding-source links are appended later.
Commit the version and notes together with the implementation being released,
then push the branch. Do not create or push a tag.

```sh
python3 scripts/release.py preflight
```

Preflight rejects uncommitted/untracked changes, mismatched versions, unfinished
notes, or an existing version tag. CI fetches all tags and repeats this check
before building. The current `0.1.4` is already published; use a new version for
the next actual release.

## 2. Build and download one candidate

Dispatch the trusted workflow on the release branch, then note its run ID:

```sh
gh workflow run build-artifacts.yml --ref main --repo palmsnipe/palm-tls
gh run list --workflow build-artifacts.yml --repo palmsnipe/palm-tls
gh run watch RUN_ID --exit-status --repo palmsnipe/palm-tls
python3 scripts/release.py fetch --run-id RUN_ID --output release-candidate
python3 scripts/release.py verify release-candidate
```

Use the branch containing your release commit if it is not `main`. The workflow
is deliberately manual and does not run private SDK jobs on pull requests or
tag pushes. The existing `PALM_TOOLCHAIN_REGISTRY_TOKEN` is only for pulling
the private toolchain image. Your local `gh` login or `GH_TOKEN` must separately
have Actions-read and repository-contents-write access for download/promotion.
Use `fetch --repo OWNER/REPO` when working in another repository.

The workflow checks the toolchain, builds/tests all seven library variants and
the release TLS Tester, then runs the **exact extracted native image** through
the independent crypto oracles on both **TI925T and PXA270**. A failed CPU test
fails the job, even though its output is also collected with `tee`.

The candidate contains:

- Six library PRCs, the TLS Tester PRC, and the complete binary ZIP.
- Checked-in release notes plus exact source/patch links.
- The two CPU validation logs.
- `candidate.json`, binding file hashes to the source commit, wolfSSL commit,
  pinned toolchain image, workflow run/attempt, and shared native image.

`fetch` requires a successful manual run of the correct workflow in the same
repository and verifies the downloaded manifest. It rejects mixed versions,
different ARM images across protocol profiles, inconsistent ZIP/individual
PRCs, bad internal checksums, changed files, symlinks and extra files.
Candidate artifacts expire after 90 days. Failed builds create no tag/release;
fix the source, commit, and build another candidate. Each run/attempt has a
distinct artifact name.

## 3. Benchmark and run the emulator regressions

Download the previous published ARM library into an ignored build directory:

```sh
mkdir -p library/build/release-baseline
gh release download v0.1.4 --repo palmsnipe/palm-tls \
  --pattern PalmTLSArm.prc --dir library/build/release-baseline
python3 scripts/release.py benchmark \
  --candidate release-candidate \
  --baseline-prc library/build/release-baseline/PalmTLSArm.prc \
  --emulator /Users/cyril/projects/cloudpilot-emu/src/uarm/cp-uarm \
  --session /Users/cyril/projects/cloudpilot-emu/web/embedded/public/session_os5.img \
  --server-python /opt/homebrew/bin/python3.12 \
  --output release-evidence
```

The local Palm toolchain/SDK, Clang, Node.js and OpenSSL CLI are needed to build
the small benchmark applications. The server Python must have TLS 1.3 support;
adjust these paths to the local installation. `--port` selects three adjacent
loopback ports (default 19443–19445); `--mips` defaults to 100.

The command freezes both library binaries, creates one eight-root P-256
certificate fixture and runs the same profiling-disabled benchmark application
twice per version. Each run measures five cold full, five warm full and five
resumed TLS 1.3 handshakes. An external Palm timer includes the entire
SessionOpen/Handshake path, including cold loading, trust and key generation.
DNS/TCP setup, later I/O and cleanup are excluded. A different negotiated cipher,
session, emulator, clock or trust fixture makes the comparison fail.

It also installs the candidate with the profiling/regression application and
checks context/trust reuse, hostname/bad-CA rejection, purge, cancellation,
cooperative slot isolation, full/resumed TLS 1.2, and balanced TLS 1.3 phase
profiles. The server independently confirms full/resumed connections.

Private working files remain under `library/build/release-checks/`: copied
sessions, PRCs, fixture private keys, screenshots and database exports. Only
validated CSVs, server records and provenance metadata enter `release-evidence`.
Do not publish the private working directory. `evidence.json` binds these files
and the recomputed comparison table to the exact candidate manifest. Measurements
are emulator results, not physical Palm or Internet latency claims.

Inspect the printed table and release notes. An increase in elapsed time is
reported honestly; there is no arbitrary percentage threshold. Use a fresh output
directory for a repeat, and do not edit raw results or manually attach substitute
evidence. No physical-device certification is implied by the emulator checks.

## 4. Promote the verified artifacts

```sh
python3 scripts/release.py publish \
  --candidate release-candidate --evidence release-evidence
```

This command:

1. Revalidates all candidate/evidence hashes and recomputes the performance table.
2. Downloads the original successful CI artifact again and requires an identical
   candidate manifest. It also verifies that the measured baseline matches the
   previous published release's ARM asset.
3. Creates an annotated version tag at the candidate commit, or checks an existing
   tag points to that exact commit. A conflicting tag stops promotion.
4. Creates/resumes a draft with the candidate's checked-in notes, measured table,
   validation-run link and corresponding-source references.
5. Uploads the unchanged PRCs/ZIP, a public benchmark ZIP, `release-manifest.json`
   and standalone `SHA256SUMS`. It verifies existing assets instead of replacing
   them and downloads every asset to check its actual bytes.
6. Publishes the draft as the latest release only after the upload checks pass.

`--draft-only` performs the same verification and leaves a draft if an additional
review is desired. Re-run the same command without that flag to publish it.
Publication is explicit; neither committing nor dispatching CI publishes a release.

The release tag stays at the implementation/candidate commit. Benchmark evidence
is produced after that build and attached to the release; it does not require a
new source commit or rebuilding the binaries. The benchmark ZIP includes the
CPU validation logs. `release-manifest.json` records the original CI candidate,
evidence manifest hash and release asset hashes; `SHA256SUMS` covers all download
assets except itself.

## Recovery and maintenance

- For an interrupted upload, rerun `publish` with the **same candidate and
  evidence**. Matching assets are reused and only missing files are uploaded.
  Download verification failure leaves an unpublished release as a draft.
- If an existing asset differs, the command stops. Investigate the mismatch;
  it will not use `--clobber` to hide a different build.
- An already-published release is read-only: an identical rerun checks the
  source, notes and assets and returns its URL. Different contents require a
  new version. Never force-update a release tag.
- Promotion rejects a candidate older than the latest published release, so
  resuming an old draft cannot accidentally downgrade the latest download.
- Keep the candidate/evidence directories until publication succeeds. To resume
  on another machine, fetch the same CI run and transfer only the public evidence
  directory; sessions/keys are not required by `publish`.
- If the CI artifact expires before promotion, build and validate a new candidate.
  If a tag/release was already created, retain the original verified inputs and
  investigate before proceeding; never replace published bytes to reuse a version.

Test release tooling locally with:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

These tests use a simulated GitHub service and temporary PRCs to exercise
corruption, provenance mismatches, conflicting tags, interrupted uploads and
idempotent retries. They never create a remote tag or release. The tests also
run as part of `make check`; the workflow can additionally be checked with
`actionlint .github/workflows/build-artifacts.yml`.
