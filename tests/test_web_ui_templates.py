import unittest


class TestWebUiTemplates(unittest.TestCase):
    def test_login_template_renders(self):
        from src import web_ui

        html = web_ui.render_login_page(error=False)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Login - LMArena Bridge", html)

    def test_dashboard_template_renders(self):
        from src import web_ui

        config = {
            "api_keys": [],
            "auth_token": "",
            "auth_tokens": [],
            "cf_clearance": "",
        }

        html = web_ui.render_dashboard_page(
            config=config,
            text_models=[],
            model_usage_stats={},
            token_status="Not Set",
            token_class="status-bad",
            cf_status="Not Set",
            cf_class="status-bad",
        )

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("LMArena Bridge Dashboard", html)

    def test_dashboard_escapes_untrusted_content(self):
        from src import web_ui

        malicious_key_name = '<img src=x onerror=alert("XSS")>'
        malicious_token = '</code><script>window.__xss__=1</script>'
        malicious_cf = '</script><script>window.__xss2__=1</script>'
        malicious_model = {
            "publicName": '<svg onload=alert(1)>',
            "organization": '<b onclick=alert(1)>ORG</b>',
            "rank": '1"><script>alert(1)</script>',
            "capabilities": {"outputCapabilities": {"text": True}},
        }

        config = {
            "api_keys": [
                {"name": malicious_key_name, "key": "test-key'\"<>", "rpm": 60, "created": 0},
            ],
            "auth_token": "",
            "auth_tokens": [malicious_token],
            "cf_clearance": malicious_cf,
        }

        model_usage_stats = {
            '</script><script>window.__xss3__=1</script>': 1,
        }

        html = web_ui.render_dashboard_page(
            config=config,
            text_models=[malicious_model],
            model_usage_stats=model_usage_stats,
            token_status="Configured",
            token_class="status-good",
            cf_status="Configured",
            cf_class="status-good",
        )

        # HTML contexts must escape angle brackets and quotes.
        self.assertIn("&lt;img", html)
        self.assertNotIn(malicious_key_name, html)
        self.assertIn("&lt;svg", html)
        self.assertNotIn(malicious_model["publicName"], html)

        # Ensure token and cf_clearance don't inject executable markup.
        self.assertNotIn(malicious_token, html)
        self.assertNotIn(malicious_cf, html)

        # Ensure JSON embedded in <script> cannot contain a raw </script> sequence from data.
        self.assertNotIn('</script><script>window.__xss3__=1</script>', html)


if __name__ == "__main__":
    unittest.main()
