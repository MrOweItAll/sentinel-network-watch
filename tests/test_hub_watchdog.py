"""Independent liveness checking must survive the hub process stopping."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from sentinel_watch import hub_cli
from sentinel_watch import alerts


class WatchdogTests(unittest.TestCase):
    def run_watchdog(self, *, active=True, overview=None, failure=None):
        fake_engine=Mock();fake_engine.tick.return_value={'ok':True,'delivery_state':'verified'}
        with tempfile.TemporaryDirectory() as folder:
            config={'state_dir':folder,'alerts_config_path':'/fixed/private/config.json'}
            with patch.object(hub_cli,'load_config',return_value=config), \
                 patch.object(hub_cli,'private_dir',return_value=Path(folder)), \
                 patch.object(hub_cli,'Hub') as cls, \
                 patch.object(hub_cli,'write_private') as writer, \
                 patch.object(alerts,'AlertEngine',return_value=fake_engine) as engine, \
                 patch.object(alerts,'load_config',return_value=Mock()), \
                 patch.object(alerts,'_subprocess_ok',return_value=active) as status, \
                 patch.object(alerts,'service_checks',return_value={'outbox_filesystem':True}):
                if failure: cls.side_effect=failure
                else: cls.return_value.overview.return_value=overview or {'ok':True}
                result=hub_cli.watchdog(Path('not-read-fixture'))
                checks=engine.call_args.kwargs['check_provider']()
                status.assert_called_once_with(['/usr/bin/systemctl','is-active','--quiet','sentinel-hub.service'])
                fake_engine.tick.assert_called_once()
                self.assertEqual(writer.call_args.args[0].name,'watchdog-status.json')
                return result,checks

    def test_service_stopped_is_not_healthy_even_if_old_status_is_fresh(self):
        result,checks=self.run_watchdog(active=False)
        self.assertFalse(checks['hub_collection'])
        self.assertFalse(result['hub_service_active'])

    def test_corrupt_hub_state_still_drains_independent_alert_outbox(self):
        result,checks=self.run_watchdog(failure=ValueError('FAKE_PRIVATE_ERROR'))
        self.assertFalse(checks['hub_collection'])
        self.assertTrue(result['ok'])
        self.assertFalse(result['complete_host_outage_detectable'])

    def test_healthy_service_and_fresh_status_pass(self):
        result,checks=self.run_watchdog()
        self.assertTrue(checks['hub_collection'])
        self.assertTrue(checks['outbox_filesystem'])


if __name__=='__main__':unittest.main()
