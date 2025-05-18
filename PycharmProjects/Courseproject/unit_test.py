import unittest
import tkinter as tk
from osint import OSINTApp

class OSINTAppTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = OSINTApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_ip_validation(self):
        self.assertTrue(self.app.is_valid_ip("8.8.8.8"))
        self.assertTrue(self.app.is_valid_ip("192.168.1.1"))
        self.assertFalse(self.app.is_valid_ip("300.100.100.100"))
        self.assertFalse(self.app.is_valid_ip("notanip"))

    def test_empty_domain_info(self):
        original_text = self.app.domain_result.get("1.0", tk.END)
        self.app.get_domain_info()
        self.assertEqual(self.app.domain_result.get("1.0", tk.END), original_text)

    def test_clear_report(self):
        self.app.report_display.insert("1.0", "Тестовый текст")
        self.app.clear_report()
        self.assertEqual(self.app.report_display.get("1.0", tk.END), "\n")

    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = OSINTApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_domain_info_basic(self):
        self.app.domain_entry.insert(0, "google.com")
        self.app.get_domain_info()
        result = self.app.domain_result.get("1.0", tk.END)
        self.assertGreater(len(result), 10)

    def test_localhost_scan(self):
        self.app.ip_entry.insert(0, "192.168.0.1")
        self.app.scan_ports()
        result = self.app.port_result.get("1.0", tk.END)
        self.assertIn("192.168.0.1", result)

    def test_cve_search_response(self):
        self.app.cve_entry.insert(0, "CVE-2021-44228")
        self.app.search_cve()
        result = self.app.cve_result.get("1.0", tk.END)
        self.assertNotIn("Error", result)

    def test_report_generation(self):
        self.app.domain_entry.insert(0, "example.com")
        self.app.ip_entry.insert(0, "8.8.8.8")

        self.app.domain_result.insert("1.0", "Domain: example.com\nIP: 8.8.8.8")
        self.app.port_result.insert("1.0", "Ports: 80, 443")

        self.app.generate_report()
        report = self.app.report_display.get("1.0", tk.END)

        self.assertIn("example.com", report)
        self.assertIn("8.8.8.8", report)


if __name__ == "__main__":
    unittest.main()