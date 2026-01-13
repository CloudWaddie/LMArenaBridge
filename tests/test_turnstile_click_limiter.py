import unittest


class TestTurnstileClickLimiter(unittest.TestCase):
    def test_budget_and_cooldown(self) -> None:
        from src.browser_automation import TurnstileClickLimiter

        limiter = TurnstileClickLimiter(max_clicks=12, cooldown_seconds=5.0)

        allowed: list[int] = []
        for t in range(0, 100):
            if limiter.try_acquire(float(t)):
                allowed.append(t)

        self.assertEqual(
            allowed,
            [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55],
        )

    def test_blocked_attempt_does_not_consume_budget(self) -> None:
        from src.browser_automation import TurnstileClickLimiter

        limiter = TurnstileClickLimiter(max_clicks=12, cooldown_seconds=5.0)

        self.assertTrue(limiter.try_acquire(0.0))
        self.assertEqual(limiter.clicks_used, 1)

        # Within cooldown window -> blocked, should not consume budget.
        self.assertFalse(limiter.try_acquire(1.0))
        self.assertEqual(limiter.clicks_used, 1)

        self.assertTrue(limiter.try_acquire(5.0))
        self.assertEqual(limiter.clicks_used, 2)

