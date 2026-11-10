import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import urllib.error

spec=importlib.util.spec_from_file_location('vendor_samples',Path(__file__).with_name('vendor-native-samples.py'))
samples=importlib.util.module_from_spec(spec);spec.loader.exec_module(samples)

class PublisherRetryTests(unittest.TestCase):
    def test_temporary_service_failure_retries_then_returns_original_response(self):
        response=object();opener=Mock()
        opener.open.side_effect=[urllib.error.HTTPError('https://publisher.test',503,'busy',{},None),response]
        with patch.object(samples.time,'monotonic',return_value=10),patch.object(samples.time,'sleep') as pause:
            self.assertIs(samples.open_sample(opener,object(),55),response)
        self.assertEqual(opener.open.call_count,2);pause.assert_called_once_with(1)

    def test_nontransient_failure_and_redirect_are_not_retried(self):
        for failure in [urllib.error.HTTPError('https://publisher.test',404,'missing',{},None),ValueError('redirect rejected')]:
            opener=Mock();opener.open.side_effect=failure
            with patch.object(samples.time,'monotonic',return_value=10),patch.object(samples.time,'sleep') as pause:
                with self.assertRaises(type(failure)):samples.open_sample(opener,object(),55)
            self.assertEqual(opener.open.call_count,1);pause.assert_not_called()

    def test_persistent_outage_fails_after_bounded_attempts(self):
        opener=Mock();opener.open.side_effect=urllib.error.URLError('offline')
        with patch.object(samples.time,'monotonic',return_value=10),patch.object(samples.time,'sleep'):
            with self.assertRaises(urllib.error.URLError):samples.open_sample(opener,object(),55)
        self.assertEqual(opener.open.call_count,3)

    def test_expired_deadline_never_starts_request(self):
        opener=Mock()
        with patch.object(samples.time,'monotonic',return_value=56):
            with self.assertRaises(TimeoutError):samples.open_sample(opener,object(),55)
        opener.open.assert_not_called()

if __name__=='__main__':unittest.main()
