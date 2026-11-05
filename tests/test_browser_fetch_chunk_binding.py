import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:  # Playwright is a runtime dependency but browsers may not be installed (e.g. CI).
    from playwright.async_api import async_playwright
except Exception:  # pragma: no cover - import guard
    async_playwright = None


REPO_ROOT = Path(__file__).resolve().parents[1]


def _extract_fetch_script() -> str:
    """Return the in-page fetch script defined by the browser transports."""
    source = (REPO_ROOT / "src" / "transport.py").read_text(encoding="utf-8")
    match = re.search(r'fetch_script = """(.*?)"""', source, re.S)
    if not match:
        raise AssertionError("fetch_script not found in src/transport.py")
    return match.group(1)


class _Handler(BaseHTTPRequestHandler):
    body = "hello-1\nhello-2\n"

    def do_GET(self):  # noqa: N802 - http.server API
        if self.path == "/data":
            payload = self.body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        page = b"<html><body>bridge test page</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.do_GET()

    def log_message(self, *args):  # silence request logging
        pass


class TestBrowserFetchChunkBinding(unittest.IsolatedAsyncioTestCase):
    """The in-page fetch must not lose the body when the reportChunk binding is missing."""

    async def asyncSetUp(self) -> None:
        if async_playwright is None:
            self.skipTest("playwright is not installed")
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._base = f"http://127.0.0.1:{self._server.server_address[1]}"

        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(headless=True)
        except Exception as exc:  # pragma: no cover - depends on the host
            await self._playwright.stop()
            self.skipTest(f"chromium unavailable: {exc}")
        self._page = await self._browser.new_page()
        await self._page.goto(self._base + "/", wait_until="domcontentloaded")

    async def asyncTearDown(self) -> None:
        browser = getattr(self, "_browser", None)
        if browser is not None:
            await browser.close()
        playwright = getattr(self, "_playwright", None)
        if playwright is not None:
            await playwright.stop()
        server = getattr(self, "_server", None)
        if server is not None:
            server.shutdown()
            server.server_close()

    async def test_body_is_returned_when_report_chunk_binding_is_missing(self) -> None:
        result = await self._page.evaluate(
            _extract_fetch_script(),
            {
                "url": self._base + "/data",
                "method": "POST",
                "body": "{}",
                "extraHeaders": {},
                "timeoutMs": 15000,
            },
        )

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("status"), 200)
        self.assertNotIn("__streaming", result)
        self.assertIn("hello-1", result.get("text") or "")
        self.assertIn("hello-2", result.get("text") or "")

    async def test_streaming_result_is_used_when_binding_exists(self) -> None:
        lines: list[str] = []

        async def _report(*args) -> None:
            lines.append(str(args[-1]))

        await self._page.expose_binding("reportChunk", _report)

        result = await self._page.evaluate(
            _extract_fetch_script(),
            {
                "url": self._base + "/data",
                "method": "POST",
                "body": "{}",
                "extraHeaders": {},
                "timeoutMs": 15000,
            },
        )

        self.assertTrue(result.get("__streaming"))
        joined = "\n".join(lines)
        self.assertIn("hello-1", joined)
        self.assertIn("hello-2", joined)
        self.assertTrue(any(line.startswith('{"__type":"meta"') for line in lines))


if __name__ == "__main__":
    unittest.main()
