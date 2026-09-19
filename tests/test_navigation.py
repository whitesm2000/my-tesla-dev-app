import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

_temp = tempfile.TemporaryDirectory()
for var, filename in [('TOKEN_STORE_PATH', 'tokens.json'), ('PRIVATE_KEY_PATH', 'private.pem'), ('PUBLIC_KEY_PATH', 'public.pem')]:
    os.environ[var] = str(Path(_temp.name) / filename)
os.environ['TESLA_API_TOKEN'] = 'test-token'
import app

loader = importlib.machinery.SourceFileLoader('tesla_cli', str(Path(__file__).resolve().parents[1] / 'cli/tesla'))
spec = importlib.util.spec_from_loader(loader.name, loader)
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)

class NavigationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app.app)
        self.headers = {'Authorization': 'Bearer test-token'}
        self.url = '/api/vehicle/test-vehicle/navigate'

    def test_vehicle_listing_uses_refresh_helper(self):
        import httpx
        response = httpx.Response(200, json={"response": []})
        with patch.object(app, '_user_token', new_callable=AsyncMock, return_value='refreshed-token') as token, patch.object(app.httpx.AsyncClient, 'get', new_callable=AsyncMock, return_value=response) as get:
            result = self.client.get('/api/vehicles', headers=self.headers)
            self.assertEqual(result.status_code, 200)
            token.assert_awaited_once()
            self.assertEqual(get.call_args.kwargs['headers']['Authorization'], 'Bearer refreshed-token')

    def test_auth_and_confirmation_prevent_forwarding(self):
        with patch.object(app, '_vehicle_command', new_callable=AsyncMock) as send:
            self.assertEqual(self.client.post(self.url+'?confirm=true', json={'destination': 'Test'}).status_code, 401)
            self.assertEqual(self.client.post(self.url, headers=self.headers, json={'destination': 'Test'}).status_code, 400)
            send.assert_not_awaited()

    def test_invalid_destinations_prevent_forwarding(self):
        with patch.object(app, '_vehicle_command', new_callable=AsyncMock) as send:
            for value in ['', '  ', 123, None, 'x' * 2001]:
                with self.subTest(value=str(value)[:20]):
                    response = self.client.post(self.url+'?confirm=true', headers=self.headers, json={'destination': value})
                    self.assertEqual(response.status_code, 422)
            send.assert_not_awaited()

    def test_payload_and_result(self):
        result = {'response': {'result': True}}
        with patch.object(app, '_vehicle_command', new_callable=AsyncMock, return_value=result) as send, patch.object(app.time, 'time', return_value=1700000000.125):
            response = self.client.post(self.url+'?confirm=true', headers=self.headers, json={'destination': '  123 Main St, Washington, DC  '})
            self.assertEqual(response.json(), result)
            send.assert_awaited_once_with('test-vehicle', 'navigation_request', {
                'type': 'share_ext_content_raw', 'value': {'android.intent.extra.TEXT': '123 Main St, Washington, DC'},
                'locale': 'en-US', 'timestamp_ms': 1700000000125})

    def test_upstream_rejection_preserved(self):
        result = {'response': {'result': False, 'reason': 'vehicle unavailable'}}
        with patch.object(app, '_vehicle_command', new_callable=AsyncMock, return_value=result):
            self.assertEqual(self.client.post(self.url+'?confirm=true', headers=self.headers, json={'destination': 'Test'}).json(), result)

    def test_cli_without_yes_never_calls_api(self):
        with patch.object(cli, 'load_config', return_value={}), patch.object(cli, 'api') as api, patch('sys.argv', ['tesla', 'navigate', 'cybertruck', 'Test']):
            with self.assertRaises(SystemExit): cli.main()
            api.assert_not_called()

    def test_cli_contract_and_rejection_exit(self):
        for result, exit_code in [({'response': {'result': True}}, None), ({'response': {'result': False, 'reason': 'asleep'}}, 1), ({'error': 'tesla_api_error'}, 1)]:
            with self.subTest(result=result), patch.object(cli, 'load_config', return_value={}), patch.object(cli, 'resolve_car', return_value={'id_s': 'test-vehicle'}), patch.object(cli, 'api', return_value=result) as api, patch('sys.argv', ['tesla', 'navigate', 'cybertruck', 'Test', '--yes']):
                if exit_code:
                    with self.assertRaises(SystemExit) as error: cli.main()
                    self.assertEqual(error.exception.code, exit_code)
                else: cli.main()
                api.assert_called_once_with({}, '/api/vehicle/test-vehicle/navigate?confirm=true', 'POST', {'destination': 'Test'})

if __name__ == '__main__':
    unittest.main()
