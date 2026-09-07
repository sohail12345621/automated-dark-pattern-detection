import unittest
from crawler.selenium_scanner import SeleniumScanner

class TestSeleniumScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SeleniumScanner(headless=True, timeout=10)

    def test_scanner_instantiation(self):
        self.assertIsNotNone(self.scanner)
        self.assertTrue(self.scanner.headless)

if __name__ == "__main__":
    unittest.main()
