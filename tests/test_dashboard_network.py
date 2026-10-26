from __future__ import annotations

import unittest

from ghost_audit.dashboard import classify_api_address


class DashboardAddressClassificationTests(unittest.TestCase):
    def test_fixed_compose_service_is_internal_only_in_compose_mode(self) -> None:
        self.assertEqual(classify_api_address("http://api:8000", connection_mode="compose_internal"),
                         "compose_internal")
        self.assertEqual(classify_api_address("http://api:8000/", connection_mode="local"),
                         "external")

    def test_loopback_addresses_are_local_in_each_mode(self) -> None:
        for address in ("http://127.0.0.1:8080", "http://localhost:8000", "http://[::1]:8080",
                        "http://127.88.1.2:8000"):
            with self.subTest(address=address):
                self.assertEqual(classify_api_address(address), "loopback")
                self.assertEqual(classify_api_address(address, connection_mode="compose_internal"),
                                 "loopback")

    def test_arbitrary_external_api_urls_are_classified_as_external(self) -> None:
        for address in ("https://audit.example.test", "http://192.0.2.9:8000",
                        "https://api.example.test:8000"):
            with self.subTest(address=address):
                self.assertEqual(classify_api_address(address), "external")

    def test_compose_mode_does_not_suppress_lookalike_or_changed_targets(self) -> None:
        for address in ("http://127.0.0.1.example:8000", "http://api:8001",
                        "https://api:8000", "http://api:8000.evil.example"):
            with self.subTest(address=address):
                self.assertEqual(classify_api_address(address, connection_mode="compose_internal"),
                                 "external")

    def test_credentials_parameters_and_malformed_ports_are_not_local(self) -> None:
        for address in ("http://user:secret@localhost:8000", "http://api:8000/?target=localhost",
                        "http://localhost:badport"):
            with self.subTest(address=address):
                self.assertEqual(classify_api_address(address, connection_mode="compose_internal"),
                                 "external")


if __name__ == "__main__":
    unittest.main()
