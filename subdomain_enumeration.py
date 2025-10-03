# subdomain_enumeration.py
"""
Threaded Subdomain Enumerator
Implements:
1. Load subdomains from subdomains.txt
2. check_subdomain() to confirm activity
3. Thread pool to check in parallel
4. Save discovered subdomains to output file
5. Use Queue + Lock to synchronize threads
"""

import argparse
import threading
import queue
import requests
import time
import os
import sys
import tempfile
import unittest
from unittest import mock
from typing import Tuple, Optional

# --- Configuration defaults
DEFAULT_WORDLIST = "subdomains.txt"
DEFAULT_OUT = "discovered_subdomains.txt"
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 3.0
USER_AGENT = "SubEnum/1.0 (+https://example.com)"

# Safe allowlist to avoid accidental scanning of third-party domains
SAFE_TARGETS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "127.0.0.1",
    "localtest.me",
}


def ensure_sample_wordlist(path: str):
    """Create a small sample wordlist if none exists."""
    if os.path.exists(path):
        return
    sample = ["www", "mail", "ftp", "api", "dev", "test", "staging", "admin"]
    with open(path, "w", encoding="utf-8") as f:
        for s in sample:
            f.write(s + "\n")


def check_subdomain(domain: str, sub: str, scheme: str, timeout: float, verify_ssl: bool) -> Tuple[str, Optional[int], Optional[Exception]]:
    """
    Attempt an HTTP GET to scheme://sub.domain
    Returns (url, status_code_or_None, exception_or_None)
    """
    url = f"{scheme}://{sub}.{domain}"
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=verify_ssl)
        return url, getattr(resp, "status_code", None), None
    except Exception as e:
        return url, None, e


class SubEnum:
    def __init__(self, domain: str, wordlist_path: str, out_path: str, threads: int = DEFAULT_THREADS, timeout: float = DEFAULT_TIMEOUT, scheme: str = "http", verify_ssl: bool = True):
        self.domain = domain.strip().lower()
        self.wordlist_path = wordlist_path
        self.out_path = out_path
        self.threads = max(1, int(threads))
        self.timeout = float(timeout)
        self.scheme = scheme
        self.verify_ssl = verify_ssl

        # synchronization primitives
        self.q = queue.Queue()
        self.lock = threading.Lock()

        # results / stats
        self.discovered = []  # list of tuples (sub, url, status)
        self.total = 0
        self.checked = 0

    def load_wordlist(self):
        """Load subdomain candidates into the queue."""
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    sub = line.strip()
                    if not sub or sub.startswith("#"):
                        continue
                    sub = sub.split()[0]
                    self.q.put(sub)
            self.total = self.q.qsize()
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {self.wordlist_path}")
            raise

    def worker(self):
        """Worker thread: get an item from queue, check it, record results."""
        while True:
            try:
                sub = self.q.get_nowait()
            except queue.Empty:
                return

            url, status, exc = check_subdomain(self.domain, sub, self.scheme, self.timeout, self.verify_ssl)

            with self.lock:
                self.checked += 1
                if status is not None:
                    self.discovered.append((sub, url, status))
                    try:
                        with open(self.out_path, "a", encoding="utf-8") as out_f:
                            out_f.write(f"{sub}.{self.domain} {url} {status}\n")
                    except Exception:
                        # Fail writing should not crash the whole scan
                        print(f"[!] Could not write to output file: {self.out_path}")
                    print(f"[+] {sub}.{self.domain} -> {status}")
            self.q.task_done()

    def run(self):
        """Run the enumeration: load wordlist, start threads, and wait for completion."""
        start = time.time()
        self.load_wordlist()
        if self.total == 0:
            print("[*] Wordlist empty, nothing to do.")
            return

        # create/clear output file before starting
        try:
            open(self.out_path, "w", encoding="utf-8").close()
        except Exception as e:
            print(f"[!] Could not prepare output file {self.out_path}: {e}")
            return

        print(f"[*] Starting: {self.total} candidates, threads={self.threads}, scheme={self.scheme}, timeout={self.timeout}s")

        # spawn workers
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)

        # wait until queue is processed
        self.q.join()

        elapsed = time.time() - start
        print(f"[*] Complete. Checked: {self.checked}/{self.total}. Discovered: {len(self.discovered)}. Time: {elapsed:.2f}s")


# --- Minimal unit tests (mocking requests so no network)
class DummyResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class SubEnumTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="subenum_test_")

    def tearDown(self):
        try:
            for name in os.listdir(self.tmpdir):
                os.remove(os.path.join(self.tmpdir, name))
            os.rmdir(self.tmpdir)
        except Exception:
            pass

    def test_check_subdomain_success(self):
        with mock.patch("requests.get", return_value=DummyResponse(200)):
            url, status, exc = check_subdomain("example.com", "www", "http", 1.0, True)
            self.assertIsNone(exc)
            self.assertEqual(status, 200)
            self.assertEqual(url, "http://www.example.com")

    def test_worker_writes_and_records(self):
        # create wordlist file with one entry
        wl = os.path.join(self.tmpdir, "wl.txt")
        out = os.path.join(self.tmpdir, "out.txt")
        with open(wl, "w", encoding="utf-8") as f:
            f.write("mysub\n")

        se = SubEnum(domain="example.com", wordlist_path=wl, out_path=out, threads=1, timeout=1.0, scheme="http", verify_ssl=True)
        se.load_wordlist()
        with mock.patch("requests.get", return_value=DummyResponse(302)):
            se.worker()  # run single worker
        # check output file
        with open(out, "r", encoding="utf-8") as f:
            data = f.read()
        self.assertIn("mysub.example.com", data)


def parse_args():
    p = argparse.ArgumentParser(description="Threaded subdomain enumerator (safe defaults)")
    p.add_argument("--domain", required=False, help="Target domain. Defaults to example.com")
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="Path to wordlist (default: subdomains.txt)")
    p.add_argument("--out", default=DEFAULT_OUT, help="Output file (default: discovered_subdomains.txt)")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Number of worker threads")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP request timeout seconds")
    p.add_argument("--scheme", choices=["http", "https"], default="http", help="Scheme to use")
    p.add_argument("--insecure", action="store_true", help="Disable SSL cert verification (for https)")
    p.add_argument("--selftest", action="store_true", help="Run unit tests (no network)")
    return p.parse_args()


def main():
    args = parse_args()

    if args.selftest:
        suite = unittest.TestLoader().loadTestsFromTestCase(SubEnumTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    domain = (args.domain or "example.com").strip().lower()
    if domain not in SAFE_TARGETS:
        print(f"[!] Refusing to run: '{domain}' is not an allowed safe target.")
        print("Edit SAFE_TARGETS in the script if you want to add an allowed domain (only do this for domains you own).")
        sys.exit(2)

    ensure_sample_wordlist(args.wordlist)

    se = SubEnum(domain=domain,
                 wordlist_path=args.wordlist,
                 out_path=args.out,
                 threads=args.threads,
                 timeout=args.timeout,
                 scheme=args.scheme,
                 verify_ssl=(not args.insecure))
    try:
        se.run()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
