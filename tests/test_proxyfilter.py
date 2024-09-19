import unittest
import asyncio
from unittest.mock import MagicMock, patch, call
from proxy.proxyfilter import ProxyFilter
from proxy.routability import Routability

class TestProxyFilter(unittest.TestCase):
    """Test suite for the ProxyFilter class."""

    def setUp(self):
        """Set up the test environment before each test method."""
        self.proxy_filter = ProxyFilter()
        self.all_proxies = [
            '8.8.8.8:80|1~provider1,provider2+5',
            '93.184.216.34:8080|1~provider3+3',
            '203.0.113.0:8888|0~+0',
            '172.217.16.142:80',
            '192.168.1.1:8080',
            '1.1.1.1:80',
            '198.51.100.0:8080',
            '10.0.0.1:3128'
        ]
        self.setup_mock_data()
        self.mock_file_operations()

    def setup_mock_data(self):
        """Set up mock data for the ProxyFilter instance."""
        self.proxy_filter.routable_addresses = {'8.8.8.8', '93.184.216.34', '172.217.16.142'}
        self.proxy_filter.unroutable_addresses = {'203.0.113.0', '192.168.1.1', '198.51.100.0', '10.0.0.1'}
        self.proxy_filter.cloudflare_addresses = {'1.1.1.1'}

    def mock_file_operations(self):
        """Mock file operations for testing."""
        self.proxy_filter.check_historical_proxies = MagicMock(return_value={
            'historical': self.all_proxies[:2],
            'working': [],
            'broken': [self.all_proxies[2]],
            'untested': [self.all_proxies[3]],
            'unroutable': ['203.0.113.0', '192.168.1.1', '198.51.100.0', '10.0.0.1'],
            'cloudflare': ['1.1.1.1'],
            'routable': ['8.8.8.8', '93.184.216.34', '172.217.16.142']
        })
        self.proxy_filter.write_proxies_to_file = MagicMock()
        self.proxy_filter.append_proxies_to_file = MagicMock()
    
    @patch.object(Routability, 'is_routable')
    @patch.object(Routability, 'is_cloudflare')
    async def process_proxies(self, mock_is_cloudflare, mock_is_routable):
        """Process the test proxies asynchronously with mocked Routability methods."""
        mock_is_routable.side_effect = lambda ip: ip in self.proxy_filter.routable_addresses
        mock_is_cloudflare.side_effect = lambda ip: ip in self.proxy_filter.cloudflare_addresses
        
        # Create a mock Routability instance
        mock_routability = MagicMock()
        mock_routability.routable_addresses = self.proxy_filter.routable_addresses
        mock_routability.invalid_addresses = self.proxy_filter.unroutable_addresses
        mock_routability.cloudflare_addresses = self.proxy_filter.cloudflare_addresses
        
        # Patch the Routability class to return our mock instance
        with patch('proxy.proxyfilter.Routability', return_value=mock_routability):
            await self.proxy_filter.process_proxies(self.all_proxies, historical=True)

    def test_final_state(self):
        """Test the final state of the ProxyFilter after processing."""
        asyncio.run(self.process_proxies())
        for ip, data in self.proxy_filter.ips.items():
            if ip in self.proxy_filter.routable_addresses:
                self.assertTrue(data['routable'], f"Expected {ip} to be routable")
            else:
                self.assertFalse(data['routable'], f"Expected {ip} to be not routable")
            
            if ip in self.proxy_filter.cloudflare_addresses:
                self.assertTrue(data['cloudflare'], f"Expected {ip} to be Cloudflare")
            else:
                self.assertFalse(data['cloudflare'], f"Expected {ip} to be not Cloudflare")

    def test_routable_status(self):
        """Test the routable status of processed proxies."""
        asyncio.run(self.process_proxies())
        for ip in self.proxy_filter.ips:
            self.assertEqual(ip in self.proxy_filter.routable_addresses, 
                             self.proxy_filter.ips[ip]['routable'], 
                             f"Mismatch in routable status for {ip}")

    def test_cloudflare_status(self):
        """Test the Cloudflare status of processed proxies."""
        asyncio.run(self.process_proxies())
        for ip in self.proxy_filter.ips:
            self.assertEqual(ip in self.proxy_filter.cloudflare_addresses, 
                             self.proxy_filter.ips[ip]['cloudflare'], 
                             f"Mismatch in Cloudflare status for {ip}")

    def test_file_operations(self):
        """Test the file operations performed during proxy processing."""
        asyncio.run(self.process_proxies())

        # Collect actual calls made to append_proxies_to_file
        actual_calls = self.proxy_filter.append_proxies_to_file.call_args_list

        # Expected calls (unordered)
        expected_calls = [
            call(['93.184.216.34:80|-1~', '172.217.16.142:80|-1~'], 'proxy/proxies/_untested_proxies.txt'),
            call(['8.8.8.8:80|1~provider1,provider2+10', '93.184.216.34:8080|1~provider3+6'], 'proxy/proxies/_working_proxies.txt'),
            call(['192.168.1.1', '203.0.113.0', '198.51.100.0', '10.0.0.1'], 'proxy/proxies/_unroutable_addresses.txt'),
            call(['1.1.1.1'], 'proxy/proxies/_cloudflare_addresses.txt'),
            call(['93.184.216.34', '8.8.8.8', '172.217.16.142'], 'proxy/proxies/_routable_addresses.txt')
        ]

        # Extract the list of proxies from the expected and actual calls
        expected_call_sets = {frozenset(call.args[0]) for call in expected_calls}
        actual_call_sets = {frozenset(call.args[0]) for call in actual_calls}

        # Compare the sets of calls to verify that the right proxies were written, ignoring order
        self.assertEqual(expected_call_sets, actual_call_sets)
        
if __name__ == '__main__':
    unittest.main()
