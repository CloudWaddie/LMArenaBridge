import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio

class TestInitialDataRobustness(unittest.IsolatedAsyncioTestCase):
    async def test_get_initial_data_retries_cloudflare(self):
        # We need to mock Camoufox and the page
        from src import main
        
        mock_page = AsyncMock()
        mock_page.title.side_effect = [
            "Just a moment...", 
            "Just a moment...", 
            "LMArena"
        ]
        mock_page.content.return_value = '{"initialModels":[]}'
        mock_page.context.cookies.return_value = []
        mock_page.wait_for_function.side_effect = [
            asyncio.TimeoutError(),
            asyncio.TimeoutError(),
            None
        ]
        
        mock_browser = AsyncMock()
        mock_browser.new_page.return_value = mock_page
        mock_browser.__aenter__.return_value = mock_browser
        
        with patch("src.main.AsyncCamoufox", return_value=mock_browser), \
             patch("src.main.click_turnstile", AsyncMock(return_value=True)) as mock_click, \
             patch("src.main.get_config", return_value={}), \
             patch("src.main.save_config"), \
             patch("src.main.save_models"), \
             patch("src.main.asyncio.sleep", AsyncMock()):
            
            await main.get_initial_data()
            
            # Should have called title multiple times (at least 3 based on our mock side_effect)
            self.assertGreaterEqual(mock_page.title.call_count, 3)
            # Should have called click_turnstile multiple times
            self.assertGreaterEqual(mock_click.call_count, 2)

if __name__ == "__main__":
    unittest.main()
