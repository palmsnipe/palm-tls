"""Reject misleading or incomplete release comparisons."""
import unittest
from release_results import load


def fixture():
    text = 'case,sample,frequency,open_ticks,load_ticks,reported_handshake_ticks,session_reused\n'
    for sample in range(5):
        for name in ('cold_full','warm_full','resumed'):
            text += f'{name},{sample},100,50,{10 if name=="cold_full" else 0},30,{int(name=="resumed")}\n'
    return text+'# complete release-v1\n'


class ReleaseResultsTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(len(load(fixture())),15)

    def test_rejects_false_resume(self):
        with self.assertRaises(ValueError):
            load(fixture().replace('resumed,0,100,50,0,30,1','resumed,0,100,50,0,30,0'))

    def test_rejects_missing_or_duplicate_samples(self):
        for text in (fixture().replace('warm_full,1,100,50,0,30,0\n',''),
                     fixture().replace('warm_full,1','warm_full,0')):
            with self.assertRaises(ValueError): load(text)

    def test_rejects_incomplete_run(self):
        with self.assertRaises(ValueError): load(fixture().replace('# complete release-v1\n',''))
