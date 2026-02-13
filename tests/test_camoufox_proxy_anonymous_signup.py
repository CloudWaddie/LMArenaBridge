from unittest.mock import AsyncMock

from tests._stream_test_utils import BaseBridgeTest


class TestCamoufoxProxyAnonymousSignup(BaseBridgeTest):
    async def test_camoufox_proxy_signup_posts_turnstile_and_recaptcha_tokens(self) -> None:
        page = AsyncMock()

        async def eval_side_effect(script, arg=None):  # noqa: ANN001
            if isinstance(script, str) and "LM_BRIDGE_MINT_RECAPTCHA_V3" in script:
                payload = arg or {}
                self.assertEqual(payload.get("sitekey"), "sitekey-1")
                self.assertEqual(payload.get("action"), "sign_up")
                return "recaptcha-token-1"

            if isinstance(script, str) and "/nextjs-api/sign-up" in script:
                payload = arg or {}
                self.assertEqual(payload.get("turnstileToken"), "turnstile-token-1")
                self.assertEqual(payload.get("recaptchaToken"), "recaptcha-token-1")
                self.assertEqual(payload.get("provisionalUserId"), "provisional-user-id-1")
                return {"status": 200, "ok": True, "body": "{\"user\": {\"id\": \"u\"}}"}

            raise AssertionError(f"Unexpected evaluate script: {str(script)[:120]}")

        page.evaluate.side_effect = eval_side_effect

        resp = await self.main._camoufox_proxy_signup_anonymous_user(
            page,
            turnstile_token="turnstile-token-1",
            provisional_user_id="provisional-user-id-1",
            recaptcha_sitekey="sitekey-1",
        )

        self.assertIsInstance(resp, dict)
        self.assertEqual(resp.get("status"), 200)

