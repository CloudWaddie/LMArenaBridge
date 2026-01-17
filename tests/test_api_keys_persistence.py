import json
import unittest

from tests._stream_test_utils import BaseBridgeTest


class TestApiKeysPersistence(BaseBridgeTest):
    async def test_get_config_normalizes_api_keys_string_list(self) -> None:
        self.setup_config({"api_keys": ["test-key-fixed-1", "test-key-fixed-2"]})

        cfg = self.main.get_config()

        keys = cfg.get("api_keys")
        self.assertIsInstance(keys, list)
        self.assertEqual(
            [k.get("key") for k in keys],
            ["test-key-fixed-1", "test-key-fixed-2"],
        )

    async def test_get_config_imports_top_level_api_key(self) -> None:
        self.setup_config({"api_keys": [], "api_key": "test-key-legacy-fixed"})

        cfg = self.main.get_config()

        keys = cfg.get("api_keys")
        self.assertIsInstance(keys, list)
        self.assertEqual([k.get("key") for k in keys], ["test-key-legacy-fixed"])

    async def test_save_config_preserves_api_keys_from_disk_by_default(self) -> None:
        # Stale in-memory config loaded with old keys.
        self.setup_config({"api_keys": [{"name": "Old", "key": "test-key-old", "rpm": 60, "created": 1704236400}]})
        stale = self.main.get_config()

        # Simulate user updating keys on disk while a long-running task holds `stale`.
        self.setup_config({"api_keys": [{"name": "New", "key": "test-key-new", "rpm": 60, "created": 1704236400}]})

        stale["cf_clearance"] = "cf-updated"
        self.main.save_config(stale)

        on_disk = json.loads(self._config_path.read_text(encoding="utf-8"))
        keys = on_disk.get("api_keys")
        self.assertIsInstance(keys, list)
        self.assertEqual([k.get("key") for k in keys], ["test-key-new"])


if __name__ == "__main__":
    unittest.main()
