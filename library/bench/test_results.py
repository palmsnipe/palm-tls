"""Checks that benchmark tooling rejects bad samples and reads status markers."""
import contextlib
import io
import runpy
import struct
import tempfile
import unittest
import zlib
import zipfile
from pathlib import Path

from results import EXPECTED_CASES, VERIFY_PHASES, extract, load, summarize
from screen import status


def csv_text():
    text = 'case,sample,iterations,elapsed,frequency,bytes_per_op\n'
    for name in sorted(EXPECTED_CASES):
        for sample in range(5):
            text += f'{name},{sample},10,20,100,0\n'
    return text


class ResultsTests(unittest.TestCase):
    def test_generator_workloads(self):
        text = csv_text()
        for name in ('p256_mul2add_generator', 'p256_mul2add_generator_right'):
            for sample in range(5):
                text += f'{name},{sample},4,20,100,0\n'
        load(text)
        with self.assertRaises(ValueError):
            load('\n'.join(line for line in text.splitlines()
                           if 'p256_mul2add_generator_right,' not in line))

    def test_exclusive_verification_phases(self):
        text = csv_text()
        for sample in range(5):
            text += f'tls12_verify,{sample},1,10,100,0\n'
            for phase in VERIFY_PHASES:
                ticks = 10 if phase == 'point' else 0
                text += f'tls12_verify_phase_{phase},{sample},1,{ticks},100,0\n'
        load(text)
        with self.assertRaises(ValueError):
            load(text.replace('tls12_verify_phase_point,0,1,10',
                              'tls12_verify_phase_point,0,1,9'))
        with self.assertRaises(ValueError):
            load('\n'.join(line for line in text.splitlines()
                           if 'tls12_verify_phase_hex,' not in line))

    def test_native_image_selection(self):
        native_image = runpy.run_path(str(Path(__file__).with_name('run-emulator.py')))['native_image']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.prc'
            for entries in ([('PadR', b'pad!'), ('armc', b'native!!')],
                            [('armc', b'native!!'), ('code', b'68k!')]):
                header = bytearray(100)
                struct.pack_into('>H', header, 76, 2)
                offset = len(header)
                payload = b''
                for i, (kind, data) in enumerate(entries):
                    struct.pack_into('>4sHI', header, 78 + i * 10, kind.encode(), 1, offset)
                    offset += len(data)
                    payload += data
                path.write_bytes(header + payload)
                self.assertEqual(native_image(path), b'native!!')

    def test_palm_database_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'export.zip'
            for complete in (True, False):
                text = csv_text() + ('# complete v1\n' if complete else '# FAILED\n')
                header = bytearray(88)
                name = b'PalmTLS Bench Results'
                header[:len(name)] = name
                header[60:68] = b'DATATbch'
                struct.pack_into('>H', header, 76, 1)
                struct.pack_into('>I', header, 78, len(header))
                with zipfile.ZipFile(path, 'w') as backup:
                    backup.writestr('PalmTLS Bench Results.pdb', header + text.encode('ascii'))
                if complete:
                    self.assertEqual(extract(path), text)
                    self.assertEqual(len(load(extract(path))), 17)
                else:
                    with self.assertRaises(ValueError):
                        extract(path)

    def test_normalization_and_comparison(self):
        baseline = load(csv_text())
        candidate = load(csv_text().replace(',10,20,100,0', ',10,10,100,0'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            summarize(candidate, baseline)
        self.assertIn('10000.000,10000.000,10000.000,,-50.00', output.getvalue())

    def test_incomplete_run(self):
        with self.assertRaises(ValueError):
            load('\n'.join(csv_text().splitlines()[:-1]))

    def test_missing_case(self):
        with self.assertRaises(ValueError):
            load('\n'.join(line for line in csv_text().splitlines() if 'p256_map,' not in line))

    def test_duplicate_sample(self):
        with self.assertRaises(ValueError):
            load(csv_text().replace(',4,10,', ',3,10,'))

    def test_below_resolution(self):
        with self.assertRaises(ValueError):
            load(csv_text().replace(',10,20,100,0', ',10,0,100,0'))

    def test_clock_mismatch(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            summarize(load(csv_text()), load(csv_text().replace(',100,0', ',1000,0')))

    def test_status_marker(self):
        def chunk(kind, data):
            return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'screen.png'
            for expected in (True, False, None):
                # Exercise both native and double-density displays.
                for scale in (1, 2):
                    width = 160 * scale
                    rows = [bytearray(b'\xff' * width * 3) for _ in range(width)]
                    pattern = [0xa5, 0x3c, 0xc3, 0x5a]
                    if expected is not None:
                        for y in range(4 * scale):
                            for x in range(8 * scale):
                                black = bool(pattern[y // scale] & (128 >> (x // scale))) == expected
                                px, py = 144 * scale + x, 136 * scale + y
                                rows[py][px * 3:px * 3 + 3] = bytes([0 if black else 255]) * 3
                    data = b''.join(b'\0' + row for row in rows)
                    path.write_bytes(b'\x89PNG\r\n\x1a\n' +
                        chunk(b'IHDR', struct.pack('>IIBBBBB', width, width, 8, 2, 0, 0, 0)) +
                        chunk(b'IDAT', zlib.compress(data)) + chunk(b'IEND', b''))
                    self.assertIs(status(path), expected)


if __name__ == '__main__':
    unittest.main()
