from unittest.mock import patch

import httpx

from tests._stream_test_utils import BaseBridgeTest


class TestDashboardErrorEscaping(BaseBridgeTest):
    async def test_dashboard_error_escapes_exception_message(self) -> None:
        session_id = "test-session"
        self.main.dashboard_sessions[session_id] = "admin"

        malicious = "<script>alert('xss')</script>"

        try:
            with patch.object(self.main, "get_config", side_effect=RuntimeError(malicious)):
                transport = httpx.ASGITransport(app=self.main.app, raise_app_exceptions=False)
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://test",
                    cookies={"session_id": session_id},
                ) as client:
                    response = await client.get("/dashboard", timeout=10.0)

            self.assertEqual(response.status_code, 500)
            self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", response.text)
            self.assertNotIn(malicious, response.text)
        finally:
            self.main.dashboard_sessions.pop(session_id, None)
