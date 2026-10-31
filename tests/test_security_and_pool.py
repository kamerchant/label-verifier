import os
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("SESSION_SECRET", "x" * 40)
os.environ.setdefault("DATABASE_URL", "postgresql://unused:unused@localhost/unused")

from fastapi import HTTPException

from app import database, main


def fake_request(client_host="10.0.0.5", forwarded=""):
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=client_host))


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        main.FAILED_ATTEMPTS.clear()

    def test_locks_ip_after_five_failures(self):
        req = fake_request()
        for _ in range(5):
            main.check_rate_limit(req, "alice")
            main.record_failed_attempt(req, "alice")
        with self.assertRaises(HTTPException) as ctx:
            main.check_rate_limit(req, "alice")
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("Retry-After", ctx.exception.headers)

    def test_username_limit_applies_across_addresses(self):
        for i in range(10):
            main.record_failed_attempt(fake_request(f"10.0.1.{i}"), "Bob")
        with self.assertRaises(HTTPException):
            main.check_rate_limit(fake_request("10.0.9.9"), "bob")

    def test_success_clears_counters(self):
        req = fake_request()
        for _ in range(4):
            main.record_failed_attempt(req, "carol")
        main.clear_failed_attempts(req, "carol")
        main.check_rate_limit(req, "carol")
        self.assertEqual(main.FAILED_ATTEMPTS, {})

    def test_forwarded_header_ignored_without_trusted_proxy(self):
        with mock.patch.object(main, "TRUSTED_PROXY_COUNT", 0):
            self.assertEqual(main.get_client_ip(fake_request("10.0.0.5", "1.2.3.4")), "10.0.0.5")

    def test_forwarded_header_uses_last_trusted_hop(self):
        with mock.patch.object(main, "TRUSTED_PROXY_COUNT", 1):
            # A client-supplied leading value must not be able to choose its own address.
            self.assertEqual(main.get_client_ip(fake_request("10.0.0.5", "6.6.6.6, 192.168.1.50")), "192.168.1.50")

    def test_missing_forwarded_header_falls_back_to_peer(self):
        with mock.patch.object(main, "TRUSTED_PROXY_COUNT", 1):
            self.assertEqual(main.get_client_ip(fake_request("10.0.0.5")), "10.0.0.5")


class FakePool:
    def __init__(self):
        self.out = 0

    def getconn(self):
        self.out += 1
        return SimpleNamespace(closed=False, rollback=lambda: None)

    def putconn(self, conn, close=False):
        self.out -= 1


class ConnectionPoolTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakePool()
        self.patches = [
            mock.patch.object(database, "connection_pool", self.fake),
            mock.patch.object(database, "_pool_slots", threading.BoundedSemaphore(2)),
            mock.patch.object(database, "POOL_WAIT_SECONDS", 0.2),
        ]
        for p in self.patches:
            p.start()
        database._checked_out.clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_raises_pool_busy_instead_of_failing_instantly(self):
        a, b = database.get_connection(), database.get_connection()
        start = time.time()
        with self.assertRaises(database.PoolBusyError):
            database.get_connection()
        self.assertGreaterEqual(time.time() - start, 0.15)
        database.release_connection(a)
        database.release_connection(b)

    def test_waiter_gets_connection_when_one_is_released(self):
        a, b = database.get_connection(), database.get_connection()
        threading.Timer(0.05, database.release_connection, args=(a,)).start()
        c = database.get_connection()
        self.assertIsNotNone(c)
        database.release_connection(b)
        database.release_connection(c)

    def test_double_release_does_not_free_extra_slot(self):
        a, b = database.get_connection(), database.get_connection()
        database.release_connection(a)
        database.release_connection(a)
        c = database.get_connection()
        with self.assertRaises(database.PoolBusyError):
            database.get_connection()
        database.release_connection(b)
        database.release_connection(c)


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify_round_trip(self):
        hashed = database.hash_password("correct horse battery")
        self.assertTrue(database.verify_password("correct horse battery", hashed))
        self.assertFalse(database.verify_password("wrong", hashed))


if __name__ == "__main__":
    unittest.main()
