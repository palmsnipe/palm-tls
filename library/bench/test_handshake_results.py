"""Check the handshake reader rejects false reuse and incomplete profiles."""
import unittest
from handshake_results import CASES, PHASES, REGRESSIONS, ECDHE_PHASES, load


def fixture():
    text='case,sample,load_ticks,handshake_ticks,post_ticks,context_reused,session_reused,ticket_ready,frequency\n'
    for case in sorted(CASES):
        cached=case.startswith('cache_') and not case.endswith('full_cold')
        resumed=case.endswith('_resumed')
        for sample in range(5):
            text+=f'{case},{sample},0,10,1,{int(cached)},{int(resumed)},1,100\n'
            for period in range(2):
                for phase in PHASES:
                    ticks=(1 if period else 10) if phase=='other' else 0
                    calls=0
                    if phase=='other' or phase=='keyshare': calls=1
                    if not cached and phase=='trust': calls=1
                    if not resumed and phase in ('signature','certificate'): calls=1
                    text+=f'# phase,{case},{sample},{period},{phase},{ticks},{calls}\n'
    for name in sorted(REGRESSIONS): text+=f'# regression,{name},passed\n'
    return text+'# complete handshake-v1\n'


class HandshakeResultsTests(unittest.TestCase):
    def test_complete(self):
        rows,phases=load(fixture())
        self.assertEqual(len(rows),30)
        self.assertEqual(len(phases),780)

    def test_detailed_ecdhe(self):
        text=fixture()
        for case in CASES:
            for sample in range(5):
                for phase in ECDHE_PHASES:
                    text+=f'# ecdhe,{case},{sample},{phase},0,1\n'
        load(text)
        with self.assertRaises(ValueError):
            load(text.replace(',multiply,0,1', ',multiply,1,1'))
        with self.assertRaises(ValueError):
            load(text.replace(',map,0,1', ',map,0,0'))
        with self.assertRaises(ValueError):
            load(text+'# ecdhe,cache_resumed,0,map,0,1\n')

    def test_false_resume(self):
        with self.assertRaises(ValueError):
            load(fixture().replace('cache_resumed,0,0,10,1,1,1','cache_resumed,0,0,10,1,1,0'))

    def test_mismatched_phase_sum(self):
        with self.assertRaises(ValueError):
            load(fixture().replace('0,other,10,1','0,other,9,1'))

    def test_missing_regressions(self):
        with self.assertRaises(ValueError):
            load('\n'.join(line for line in fixture().splitlines() if '# regression,purge,' not in line))

    def test_incomplete_samples(self):
        with self.assertRaises(ValueError):
            load('\n'.join(line for line in fixture().splitlines() if not line.startswith('cache_full_cold,0,')))

    def test_cached_context_reparsed_trust(self):
        with self.assertRaises(ValueError):
            load(fixture().replace('cache_full_warm,0,0,trust,0,0','cache_full_warm,0,0,trust,0,1'))

if __name__=='__main__': unittest.main()
