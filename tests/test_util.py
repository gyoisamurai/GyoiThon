import sys
import os
from unittest.mock import MagicMock

# Add root directory to path so util can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mocking missing dependencies
mock_urllib3 = MagicMock()
sys.modules['urllib3'] = mock_urllib3
sys.modules['urllib3.util'] = mock_urllib3.util
sys.modules['chardet'] = MagicMock()

import unittest
from util import Utilty

class TestExtractSubdomain(unittest.TestCase):
    def setUp(self):
        self.util = Utilty()

    def test_extract_subdomain_standard(self):
        """Test with a standard www subdomain."""
        self.assertEqual(self.util.extract_subdomain("www.example.com", "example.com"), "www.")

    def test_extract_subdomain_deep(self):
        """Test with multiple levels of subdomains."""
        self.assertEqual(self.util.extract_subdomain("dev.www.example.com", "example.com"), "dev.www.")

    def test_extract_subdomain_exact_match(self):
        """Test where target_fqdn is exactly the domain. Should return empty string."""
        self.assertEqual(self.util.extract_subdomain("example.com", "example.com"), "")

    def test_extract_subdomain_no_match(self):
        """Test where domain is not in target_fqdn."""
        self.assertEqual(self.util.extract_subdomain("example.net", "example.com"), "")

    def test_extract_subdomain_suffix_match_not_subdomain(self):
        """
        Test where target_fqdn ends with domain but is not a proper subdomain (no dot).
        Should return empty string.
        """
        self.assertEqual(self.util.extract_subdomain("myexample.com", "example.com"), "")

    def test_extract_subdomain_domain_in_middle(self):
        """
        Test where domain appears in the middle of target_fqdn.
        Should probably return empty string if we only care about subdomains of that domain.
        """
        self.assertEqual(self.util.extract_subdomain("www.example.com.extra", "example.com"), "")

if __name__ == '__main__':
    unittest.main()
