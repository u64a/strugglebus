"""Standalone stdlib checks for the inert design prototype, not application tests."""

from contextlib import closing
from html.parser import HTMLParser
from http.client import HTTPConnection
from http.server import HTTPServer
import json
from threading import Thread
import unittest
from urllib.parse import urlencode

import preview


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def matching(self, tag):
        return [attrs for kind, attrs in self.elements if kind == tag]


class RenderingChecks(unittest.TestCase):
    def test_every_view_and_state_is_inert_and_labeled(self):
        for view in preview.VIEWS:
            for state in preview.STATES:
                with self.subTest(view=view, state=state):
                    text = preview.render(view, state, {}).decode()
                    document = Document(text)
                    self.assertIn("DESIGN PREVIEW", text)
                    self.assertIn("Synthetic data. No live bus or live actions.", text)
                    self.assertEqual(len(document.matching("main")), 1)
                    self.assertEqual(len(document.matching("h1")), 1)
                    self.assertFalse(document.matching("script"))
                    self.assertFalse(document.matching("iframe"))
                    ids = [attrs["id"] for _, attrs in document.elements if "id" in attrs]
                    self.assertEqual(len(ids), len(set(ids)))
                    for attrs in document.matching("input"):
                        if attrs.get("type") != "hidden":
                            self.assertIn("disabled", attrs)
                    for attrs in document.matching("button"):
                        if attrs.get("type") != "submit":
                            self.assertIn("disabled", attrs)
                    for attrs in document.matching("form"):
                        self.assertEqual(attrs, {"method": "get", "action": "/", "class": "filters"})
                    for attrs in document.matching("a"):
                        self.assertTrue(attrs["href"].startswith(("/", "#")))
                    if state == "unavailable" and view != "login":
                        self.assertNotIn('class="metric"', text)
                        self.assertNotIn('class="pill good"', text)
                        self.assertIn("not an empty result", text)

    def test_filters_select_only_matching_synthetic_messages(self):
        text = preview.activity("normal", {"agent": "atlas-worker", "channel": "help"})
        document = Document(text)
        self.assertEqual(len(document.matching("article")), 1)
        self.assertIn("Sequence 1041", text)
        self.assertNotIn("Sequence 1042", text)
        self.assertIn("Nothing on this page", preview.activity("normal", {"agent": "build-worker", "channel": "help"}))

    def test_frozen_and_stale_remain_distinct(self):
        frozen = preview.render("board", "frozen", {}).decode()
        stale = preview.render("board", "stale", {}).decode()
        self.assertIn("Agent access is frozen", frozen)
        self.assertIn("Creating or restoring access is paused", frozen)
        self.assertIn("not current state", stale)
        self.assertNotIn("Agent access is frozen", stale)
        self.assertIn("Access creation is paused", preview.enroll("frozen", {}))

    def test_empty_examples_do_not_invent_data(self):
        board = preview.board("empty", {})
        self.assertIn("Nothing has been posted yet", board)
        self.assertNotIn("1042", board)
        self.assertNotIn('class="pill ">42', board)
        self.assertIn("No eligible candidates", preview.appearance("empty", {}))
        self.assertNotIn("Open review specimen", preview.appearance("empty", {}))

    def test_options_reject_unknown_duplicate_and_oversized_input(self):
        for query in (
            "view=unknown", "state=unknown", "view=board&view=activity",
            "token=do-not-reflect", "channel=unknown", "agent=unknown",
            "view=board&state=normal&channel=&agent=&extra=1", "x=" + "a" * 511,
        ):
            with self.subTest(query=query[:50]):
                with self.assertRaises(ValueError):
                    preview.options(query)
        self.assertEqual(preview.options("")[0:2], ("board", "normal"))
        query = urlencode({"view": "activity", "state": "normal", "agent": "atlas-worker", "channel": "help"})
        self.assertEqual(preview.options(query)[2]["agent"], "atlas-worker")

    def test_metadata_and_body_are_text_not_executable_markup(self):
        original = preview.MESSAGES
        self.addCleanup(setattr, preview, "MESSAGES", original)
        preview.MESSAGES = (("1", "atlas-worker", "AW", "help", "chat", "09:41", '<script>alert("not executable")</script>'),)
        text = preview.message_rows("normal")
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)


class HTTPChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), preview.Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        if cls.thread.is_alive():
            raise RuntimeError("Prototype check server did not stop.")

    def request(self, path="/", *, method="GET", headers=None):
        with closing(HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)) as client:
            client.request(method, path, headers=headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()

    def test_health_css_and_policy(self):
        code, headers, body = self.request("/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"prototype": "console-design-a", "synthetic": True, "writes": False})
        self.assertIn("script-src 'none'", headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Set-Cookie", headers)
        code, headers, body = self.request("/preview.css")
        self.assertEqual(code, 200)
        self.assertEqual(body, preview.CSS.read_bytes())
        self.assertTrue(headers["Content-Type"].startswith("text/css"))

    def test_no_actions_or_generic_file_serving(self):
        for path in ("/", "/operator/presentation/activate", "/operator/session"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path, method="POST")[0], 405)
        for path in ("/preview.py", "/check_preview.py", "/../AGENTS.md", "/%2e%2e/AGENTS.md"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_invalid_options_and_foreign_hosts_fail(self):
        code, _, body = self.request("/?token=do-not-reflect")
        self.assertEqual(code, 400)
        self.assertNotIn(b"do-not-reflect", body)
        self.assertEqual(self.request("/", headers={"Host": "example.invalid"})[0], 421)
        self.assertEqual(self.request("/?view=board&view=activity")[0], 400)
        self.assertEqual(self.request("/?view=" + "a" * 513)[0], 400)


if __name__ == "__main__":
    unittest.main()
