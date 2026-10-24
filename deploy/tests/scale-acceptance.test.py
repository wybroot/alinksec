import importlib.util,math,unittest,uuid
from pathlib import Path

spec=importlib.util.spec_from_file_location('scale_acceptance',Path(__file__).with_name('scale-acceptance.py'))
scale=importlib.util.module_from_spec(spec);spec.loader.exec_module(scale)

class ScaleVerdictTest(unittest.TestCase):
    def test_tail_latency_cannot_disappear_into_an_average(self):
        self.assertEqual(scale.summary([1]*94+[2000]*6)['p95Millis'],2000)
        self.assertEqual(scale.summary([1,2,3,4,100])['p99Millis'],100)
    def test_missing_negative_and_nonfinite_measurements_are_rejected(self):
        for values in [[],[-1],[math.nan],[math.inf],[1,-math.inf]]:
            with self.subTest(values=values),self.assertRaises(AssertionError):scale.summary(values)
    def test_database_filter_is_bounded_and_contains_only_fixture_uuids(self):
        value=str(uuid.uuid4());self.assertEqual(scale.quoted([value]),"'"+value+"'")
        for values in [["' OR 1=1 --"],[value]*4097]:
            with self.assertRaises(AssertionError):scale.quoted(values)

if __name__=='__main__':unittest.main()
