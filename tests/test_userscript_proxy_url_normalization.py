from tests._stream_test_utils import BaseBridgeTest


class TestUserscriptProxyUrlNormalization(BaseBridgeTest):
    def test_normalizes_lmarena_urls_to_paths(self) -> None:
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("https://lmarena.ai/nextjs-api/stream/create-evaluation"),
            "/nextjs-api/stream/create-evaluation",
        )
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("https://arena.ai/nextjs-api/sign-up?x=1"),
            "/nextjs-api/sign-up?x=1",
        )
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("/nextjs-api/stream/create-evaluation"),
            "/nextjs-api/stream/create-evaluation",
        )
        self.assertEqual(
            self.main._normalize_userscript_proxy_url("https://example.com/foo"),
            "https://example.com/foo",
        )

