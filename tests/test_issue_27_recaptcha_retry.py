import httpx
from fastapi.testclient import TestClient


def test_issue_27_recaptcha_validation_failed_triggers_retry(monkeypatch):
    # Ensure local repo paths take precedence over any installed `src` package.
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))

    import src.main as main

    main.app.dependency_overrides[main.rate_limit_api_key] = lambda: {"key": "test-api-key", "rpm": 60}

    monkeypatch.setattr(
        main,
        "get_models",
        lambda: [
            {
                "publicName": "test-model",
                "id": "test-model-id",
                "organization": "test-org",
                "capabilities": {
                    "inputCapabilities": {"text": True},
                    "outputCapabilities": {"text": True},
                },
            }
        ],
    )

    monkeypatch.setattr(main, "save_config", lambda config: None)
    monkeypatch.setattr(main, "get_request_headers", lambda: {})
    monkeypatch.setattr(main, "get_request_headers_with_token", lambda token: {})
    monkeypatch.setattr(main, "get_next_auth_token", lambda exclude_tokens=None: "arena-auth-prod-v1-token")

    issued_tokens = ["token-1", "token-2"]

    async def fake_refresh_recaptcha_token(force: bool = False):
        return issued_tokens.pop(0)

    monkeypatch.setattr(main, "refresh_recaptcha_token", fake_refresh_recaptcha_token)

    request_count = {"n": 0}

    async def fake_post(self, url, json=None, headers=None, timeout=None):
        request_count["n"] += 1
        request = httpx.Request("POST", url)

        if request_count["n"] == 1:
            return httpx.Response(
                400,
                json={"error": "recaptcha validation failed"},
                request=request,
            )

        return httpx.Response(
            200,
            text='a0:"Hello"\nad:{"finishReason":"stop"}\n',
            request=request,
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = TestClient(main.app)
    response = client.post(
        "/api/v1/chat/completions",
        json={
            "model": "test-model",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
        },
    )
    data = response.json()

    assert "error" not in data
    assert data["choices"][0]["message"]["content"] == "Hello"
    assert request_count["n"] == 2

    main.app.dependency_overrides.clear()
