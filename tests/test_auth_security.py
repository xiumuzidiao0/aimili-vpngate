import unittest

import auth_security
import vpngate_manager


class PasswordSecurityTests(unittest.TestCase):
    def test_scrypt_hash_verifies_without_storing_plaintext(self):
        encoded = auth_security.hash_password("correct horse battery staple", salt=b"0123456789abcdef")

        self.assertTrue(encoded.startswith("scrypt$16384$8$1$"))
        self.assertNotIn("correct horse", encoded)
        self.assertTrue(auth_security.verify_password("correct horse battery staple", encoded))
        self.assertFalse(auth_security.verify_password("wrong password", encoded))

    def test_migrate_password_replaces_legacy_plaintext(self):
        config = {"username": "admin", "password": "legacy-secret"}

        changed = auth_security.migrate_password(config)

        self.assertTrue(changed)
        self.assertNotIn("password", config)
        self.assertTrue(auth_security.verify_password("legacy-secret", config["password_hash"]))

    def test_set_password_replaces_existing_hash(self):
        config = {"password_hash": auth_security.hash_password("old")}

        auth_security.set_password(config, "new")

        self.assertFalse(auth_security.verify_password("old", config["password_hash"]))
        self.assertTrue(auth_security.verify_password("new", config["password_hash"]))

    def test_malformed_hash_is_rejected(self):
        for encoded in ("", "sha256$value", "scrypt$1$8$1$bad$bad", None):
            self.assertFalse(auth_security.verify_password("password", encoded))


class WebAuthGuardTests(unittest.TestCase):
    def setUp(self):
        vpngate_manager.login_attempts.clear()

    def test_login_rate_limit_clears_after_success(self):
        for index in range(vpngate_manager.LOGIN_ATTEMPT_LIMIT):
            vpngate_manager.record_login_result("192.0.2.10", False, now=100 + index)

        self.assertTrue(vpngate_manager.login_is_rate_limited("192.0.2.10", now=200))
        vpngate_manager.record_login_result("192.0.2.10", True, now=201)
        self.assertFalse(vpngate_manager.login_is_rate_limited("192.0.2.10", now=201))

    def test_expired_login_attempts_do_not_block(self):
        for _ in range(vpngate_manager.LOGIN_ATTEMPT_LIMIT):
            vpngate_manager.record_login_result("192.0.2.11", False, now=10)

        self.assertFalse(
            vpngate_manager.login_is_rate_limited(
                "192.0.2.11",
                now=10 + vpngate_manager.LOGIN_ATTEMPT_WINDOW_SECONDS + 1,
            )
        )

    def test_same_origin_guard_rejects_cross_site_requests(self):
        same_origin = type("Request", (), {"headers": {"Host": "vpn.example.com:8787", "Origin": "https://vpn.example.com:8787"}})()
        cross_origin = type("Request", (), {"headers": {"Host": "vpn.example.com:8787", "Origin": "https://attacker.example"}})()
        fetch_cross_site = type("Request", (), {"headers": {"Host": "vpn.example.com:8787", "Sec-Fetch-Site": "cross-site"}})()

        self.assertTrue(vpngate_manager.Handler.is_same_origin_request(same_origin))
        self.assertFalse(vpngate_manager.Handler.is_same_origin_request(cross_origin))
        self.assertFalse(vpngate_manager.Handler.is_same_origin_request(fetch_cross_site))


if __name__ == "__main__":
    unittest.main()
