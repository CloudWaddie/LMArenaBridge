from tests._stream_test_utils import BaseBridgeTest


class TestArenaOriginAndCookieScoping(BaseBridgeTest):
    def test_detect_arena_origin(self) -> None:
        self.assertEqual(self.main._detect_arena_origin(None), "https://lmarena.ai")
        self.assertEqual(self.main._detect_arena_origin(""), "https://lmarena.ai")
        self.assertEqual(self.main._detect_arena_origin("about:blank"), "https://lmarena.ai")
        self.assertEqual(self.main._detect_arena_origin("https://lmarena.ai/?mode=direct"), "https://lmarena.ai")
        self.assertEqual(self.main._detect_arena_origin("https://arena.ai/?mode=direct"), "https://arena.ai")
        self.assertEqual(self.main._detect_arena_origin("https://www.arena.ai/foo"), "https://arena.ai")

    def test_arena_origin_candidates(self) -> None:
        self.assertEqual(
            self.main._arena_origin_candidates("https://arena.ai/nextjs-api/sign-up"),
            ["https://arena.ai", "https://lmarena.ai"],
        )
        self.assertEqual(
            self.main._arena_origin_candidates("https://lmarena.ai/nextjs-api/stream/create-evaluation"),
            ["https://lmarena.ai", "https://arena.ai"],
        )

    def test_arena_auth_cookie_specs_scope_to_both_origins(self) -> None:
        specs = self.main._arena_auth_cookie_specs("base64-token-1", page_url="https://arena.ai/?mode=direct")
        self.assertEqual(len(specs), 2)
        urls = [str(c.get("url") or "") for c in specs]
        self.assertEqual(urls, ["https://arena.ai", "https://lmarena.ai"])
        for cookie in specs:
            self.assertEqual(cookie.get("name"), "arena-auth-prod-v1")
            self.assertEqual(cookie.get("value"), "base64-token-1")
            self.assertEqual(cookie.get("path"), "/")

    def test_provisional_user_id_cookie_specs_include_host_and_domain(self) -> None:
        specs = self.main._provisional_user_id_cookie_specs("prov-1", page_url="https://lmarena.ai/?mode=direct")
        self.assertEqual(len(specs), 4)
        urls = {str(c.get("url") or "") for c in specs if c.get("url")}
        domains = {str(c.get("domain") or "") for c in specs if c.get("domain")}
        self.assertEqual(urls, {"https://lmarena.ai", "https://arena.ai"})
        self.assertEqual(domains, {".lmarena.ai", ".arena.ai"})

