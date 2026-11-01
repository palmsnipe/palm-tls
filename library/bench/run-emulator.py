#!/usr/bin/env python3
"""Run the benchmark on a private copy of a supplied cp-uarm session."""
import argparse
import hashlib
import json
import queue
import shutil
import struct
import subprocess
import threading
import time
from pathlib import Path

from results import extract, load
from screen import status


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_image(path):
    data = path.read_bytes()
    count = struct.unpack_from('>H', data, 76)[0]
    for i in range(count):
        kind, number, start = struct.unpack_from('>4sHI', data, 78 + i * 10)
        if kind == b'armc' and number == 1:
            end = struct.unpack_from('>I', data, 94 + i * 10)[0] if i + 1 < count else len(data)
            return data[start:end]
    raise ValueError(f'no native ARM image in {path}')


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    session = output / 'session.img'
    shutil.copyfile(args.session, session)
    # Freeze the inputs before booting. A later build must not replace a PRC
    # between hashing it and installing it into the emulator.
    prc = output / 'PalmTLSBench.prc'
    shutil.copyfile(args.prc, prc)
    library = output / 'PalmTLSArm.prc' if args.library else None
    if library:
        shutil.copyfile(args.library, library)
    native = native_image(prc)
    if library and native_image(library) != native:
        raise ValueError('benchmark and library must contain the same native ARM image')
    command = [str(args.emulator.resolve()), '--mips', str(args.mips), '--no-sound',
               '--device', args.device, str(session)]
    repo = Path(__file__).resolve().parents[2]
    metadata = {'benchmark_version': 1, 'mips': args.mips, 'device': args.device,
                'session_sha256': sha256(args.session),
                'emulator_sha256': sha256(args.emulator),
                'prc_sha256': sha256(prc),
                'library_sha256': sha256(library) if library else None,
                'arm_image_sha256': hashlib.sha256(native).hexdigest(),
                'arm_image_bytes': len(native),
                'git_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
                'git_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=repo, text=True)),
                'command': command}
    config = repo / 'library/build/palm/armlet-config'
    metadata['local_arm_build_config'] = config.read_text().strip() if config.exists() else None
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    messages = queue.Queue()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1)
    log = (output / 'emulator.log').open('w')

    def reader():
        for line in process.stdout:
            log.write(line)
            log.flush()
            messages.put(line)
        messages.put(None)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    deadline = time.monotonic() + args.timeout

    def send(command, expected=None, timeout=30):
        if process.poll() is not None:
            raise RuntimeError('emulator exited; see emulator.log')
        # Clear responses from earlier commands before sending a new command.
        while not messages.empty():
            messages.get_nowait()
        log.write('COMMAND: ' + command + '\n')
        log.flush()
        process.stdin.write(command + '\n')
        process.stdin.flush()
        if expected:
            end = min(deadline, time.monotonic() + timeout)
            while time.monotonic() < end:
                try:
                    line = messages.get(timeout=min(1, max(0.01, end - time.monotonic())))
                except queue.Empty:
                    continue
                if line is None:
                    raise RuntimeError('emulator exited; see emulator.log')
                if expected in line:
                    return
                if any(word in line.lower() for word in
                       ('failed', 'error', 'fatal', 'not currently possible', 'unable',
                        'cannot', 'out of memory', 'corrupt', 'not supported')):
                    raise RuntimeError(line.strip())
            raise TimeoutError(f'timed out waiting for {expected!r}; see emulator.log')

    try:
        # Boot and session restoration are asynchronous. Retry the read-only
        # readiness query before mutating the private session.
        while True:
            try:
                send('automation-status', 'automation ready', timeout=2)
                break
            except TimeoutError:
                if time.monotonic() >= deadline:
                    raise
        time.sleep(2)
        def install(path):
            if any(ch in str(path.resolve()) for ch in '\r\n"'):
                raise ValueError('CLI paths cannot contain quotes or newlines')
            while True:
                try:
                    send(f'install "{path.resolve()}"', 'installation successful')
                    return
                except RuntimeError as error:
                    # UI readiness can precede the ROM's install safe point.
                    if 'not currently possible' not in str(error) or time.monotonic() >= deadline:
                        raise
                    time.sleep(2)
        if library:
            install(library)
        install(prc)
        while True:
            try:
                send('launch "PalmTLS Bench"', 'launch successful')
                break
            except RuntimeError as error:
                if 'unable to prepare syscall' not in str(error) or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        # LCD reads do not execute emulated OS calls. Do not export databases
        # until the app reaches its completion screen, to avoid perturbing
        # samples with CLI-initiated Palm OS work.
        while time.monotonic() < deadline:
            time.sleep(5)
            screenshot = output / 'progress.png'
            send(f'screenshot "{screenshot}"', 'screenshot saved')
            state = status(screenshot)
            if state is False:
                raise RuntimeError('benchmark failed; see progress.png')
            if state is None:
                continue
            archive = output / 'databases.zip'
            send(f'db-export "{archive}"', 'export written to', timeout=args.timeout)
            text = extract(archive)
            load(text)
            (output / 'results.csv').write_text(text)
            shutil.copyfile(screenshot, output / 'complete.png')
            print(output / 'results.csv', flush=True)
            return
        raise TimeoutError('benchmark did not finish')
    finally:
        if process.poll() is None:
            process.stdin.write('quit\n')
            process.stdin.flush()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        thread.join(timeout=2)
        log.close()


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emulator', type=Path, required=True)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory for this run')
    parser.add_argument('--prc', type=Path, default=root / 'build/bench/PalmTLSBench.prc')
    parser.add_argument('--library', type=Path, help='optional ARM library to install for engine timings')
    parser.add_argument('--mips', type=int, default=100)
    parser.add_argument('--device', choices=['auto', 'e2', 'zire72', 'tx'], default='auto')
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if args.mips <= 0 or args.timeout <= 0:
        parser.error('--mips and --timeout must be positive')
    run(args)


if __name__ == '__main__':
    main()
