"""Profile configuration fixtures: no real services or network."""
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest import mock

from sentinel_watch import alerts
import test_alerts as fixtures


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.AlertEngineTests('test_pending_event_survives_restart_and_is_sent_once')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.config=self.fixture.config

    def test_default_profile_probes_only_the_selected_state_filesystem(self):
        state=Path(self.fixture.directory.name)/'configured-outbox'
        with mock.patch.object(alerts,'_outbox_filesystem_ok',return_value=True) as filesystem, \
             mock.patch.object(alerts,'_subprocess_ok',side_effect=AssertionError('no subprocess')), \
             mock.patch.object(alerts,'_container_running',side_effect=AssertionError('no docker')), \
             mock.patch.object(alerts,'_dns_check',side_effect=AssertionError('no DNS')), \
             mock.patch.object(alerts,'_web_check',side_effect=AssertionError('no HTTP')):
            self.assertEqual(alerts.service_checks(self.config,state),{'outbox_filesystem':True})
        filesystem.assert_called_once_with(state)

    def test_adguard_profile_uses_explicit_ports_and_container(self):
        config=replace(self.config,health_profile='adguard',dns_port=15353,
                       web_port=18080,container_name='fixture-adguard')
        with mock.patch.object(alerts,'_outbox_filesystem_ok',return_value=True), \
             mock.patch.object(alerts,'_subprocess_ok',return_value=True), \
             mock.patch.object(alerts,'_container_running',return_value=True) as container, \
             mock.patch.object(alerts,'_dns_check',return_value=True) as dns, \
             mock.patch.object(alerts,'_web_check',return_value=True) as web, \
             mock.patch.object(alerts,'ROUTER_COLLECTOR_TIMER',mock.Mock(exists=lambda:False)):
            result=alerts.service_checks(config,self.fixture.state)
        self.assertEqual(set(result),{'outbox_filesystem','docker_service','adguard_container',
                                      'dns_udp','dns_tcp','adguard_web'})
        container.assert_called_once_with('fixture-adguard')
        self.assertEqual(dns.call_args_list,[mock.call(False,15353),mock.call(True,15353)])
        web.assert_called_once_with(18080)

    def test_engine_default_provider_passes_actual_state_directory(self):
        state=Path(self.fixture.directory.name)/'other-outbox'
        engine=alerts.AlertEngine(state,self.config,transport=self.fixture.http,
                                  clock=self.fixture.clock,boot_id_provider=lambda:'unknown')
        with mock.patch.object(alerts,'service_checks',return_value={'outbox_filesystem':True}) as checks:
            self.assertEqual(engine.check_provider(),{'outbox_filesystem':True})
        checks.assert_called_once_with(self.config,state)

    def test_config_rejects_unknown_profiles_invalid_ports_or_container(self):
        for changes in ({'health_profile':'all'}, {'dns_port':True}, {'dns_port':0},
                        {'web_port':65536}, {'container_name':'invalid/name'}):
            with self.subTest(changes=changes),self.assertRaises(alerts.SafeError):
                replace(self.config,**changes).validate()

    def test_private_config_loads_explicit_profile_and_defaults_to_outbox(self):
        path=Path(self.fixture.directory.name)/'config.json'
        value={'base_url':'https://ntfy.test.invalid','topic':'fixture-topic'}
        path.write_text(json.dumps(value),encoding='utf-8');path.chmod(0o600)
        self.assertEqual(alerts.load_config(path).health_profile,'outbox')
        value.update(health_profile='adguard',dns_port=15353,web_port=18080,
                     container_name='fixture-adguard')
        path.write_text(json.dumps(value),encoding='utf-8')
        loaded=alerts.load_config(path)
        self.assertEqual((loaded.health_profile,loaded.dns_port,loaded.web_port,loaded.container_name),
                         ('adguard',15353,18080,'fixture-adguard'))


if __name__=='__main__':unittest.main()
