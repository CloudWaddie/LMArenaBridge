param(
  [string]$ServerHost = "127.0.0.1",
  [int]$Port = 8000,
  [string]$Model = "gemini-3-pro-grounding",
  [string]$Prompt = "What model is it? Reply with only the model name.",
  [switch]$IncludeDashboard,
  [string]$DashboardPassword = "admin",
  [string]$ApiKey = "",
  [switch]$NoStartServer,
  [int]$StartupTimeoutSec = 180,
  [int]$StreamTimeoutSec = 300,
  [switch]$EnforceTurnstileClickGuard,
  [int]$MaxTurnstileClicks = 15,
  [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BaseUrl = "http://$ServerHost`:$Port"

$outLog = Join-Path $RepoRoot "tmp_e2e_server_out.log"
$errLog = Join-Path $RepoRoot "tmp_e2e_server_err.log"

if (Test-Path $outLog) { Remove-Item $outLog -Force }
if (Test-Path $errLog) { Remove-Item $errLog -Force }

function Get-ApiKeyFromConfig {
  param([string]$ConfigPath)
  try {
    $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
  } catch {
    return ""
  }
  if ($null -eq $cfg) { return "" }
  $keys = $cfg.api_keys
  if ($null -eq $keys -or $keys.Count -lt 1) { return "" }
  $k = $keys[0].key
  if ($null -eq $k) { return "" }
  return [string]$k
}

$proc = $null
try {
  if (-not $NoStartServer) {
    $proc = Start-Process -FilePath python -ArgumentList @("-u", "src/main.py") -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $outLog -RedirectStandardError $errLog
  }

  # Wait for health
  $healthy = $false
  $deadline = (Get-Date).AddSeconds($StartupTimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-WebRequest -Uri "$BaseUrl/api/v1/health" -TimeoutSec 2
      if ($resp.StatusCode -eq 200) { $healthy = $true; break }
    } catch {
      Start-Sleep -Seconds 1
    }
  }
  if (-not $healthy) {
    throw "Server did not become healthy within ${StartupTimeoutSec}s. See $outLog / $errLog"
  }

  if (-not $ApiKey) {
    $ApiKey = [string]$env:LMABRIDGE_SMOKE_API_KEY
  }
  if (-not $ApiKey) {
    $ApiKey = Get-ApiKeyFromConfig -ConfigPath (Join-Path $RepoRoot "config.json")
  }

  $env:LMABRIDGE_E2E_BASEURL = $BaseUrl
  $env:LMABRIDGE_E2E_MODEL = $Model
  $env:LMABRIDGE_E2E_PROMPT = $Prompt
  $env:LMABRIDGE_E2E_STREAM_TIMEOUT = [string]$StreamTimeoutSec
  $env:LMABRIDGE_E2E_INCLUDE_DASHBOARD = $(if ($IncludeDashboard) { "1" } else { "0" })
  $env:LMABRIDGE_E2E_DASHBOARD_PASSWORD = $DashboardPassword
  $env:LMABRIDGE_E2E_API_KEY = $ApiKey
  $env:LMABRIDGE_E2E_CONFIG_PATH = (Join-Path $RepoRoot "config.json")

  @'
import json
import os
import sys
import time

import httpx
import ctypes
from ctypes import wintypes

base = os.environ["LMABRIDGE_E2E_BASEURL"]
model = os.environ.get("LMABRIDGE_E2E_MODEL", "gemini-3-pro-grounding")
prompt = os.environ.get("LMABRIDGE_E2E_PROMPT", "What model is it? Reply with only the model name.")
timeout_seconds = int(os.environ.get("LMABRIDGE_E2E_STREAM_TIMEOUT", "300") or "300")
include_dashboard = os.environ.get("LMABRIDGE_E2E_INCLUDE_DASHBOARD", "0") == "1"
dashboard_password = os.environ.get("LMABRIDGE_E2E_DASHBOARD_PASSWORD", "admin")
api_key = (os.environ.get("LMABRIDGE_E2E_API_KEY") or "").strip()
config_path = os.environ.get("LMABRIDGE_E2E_CONFIG_PATH", "")

headers = {}
if api_key:
    headers["Authorization"] = f"Bearer {api_key}"

def fail(msg: str) -> None:
    raise SystemExit(msg)

def _enum_windows_titles() -> list[tuple[int, str]]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    EnumWindows = user32.EnumWindows
    EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM), wintypes.LPARAM]
    EnumWindows.restype = wintypes.BOOL

    GetWindowTextLengthW = user32.GetWindowTextLengthW
    GetWindowTextLengthW.argtypes = [wintypes.HWND]
    GetWindowTextLengthW.restype = ctypes.c_int

    GetWindowTextW = user32.GetWindowTextW
    GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    GetWindowTextW.restype = ctypes.c_int

    out: list[tuple[int, str]] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def _cb(hwnd, lparam):  # noqa: ANN001
        try:
            length = int(GetWindowTextLengthW(hwnd) or 0)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            if GetWindowTextW(hwnd, buf, length + 1) <= 0:
                return True
            title = str(buf.value or "")
            if title:
                out.append((int(hwnd), title))
        except Exception:
            return True
        return True

    EnumWindows(_cb, 0)
    return out

def _find_hwnd_by_title_substring(needle: str, timeout_s: float = 20.0) -> int:
    needle_cf = (needle or "").casefold()
    deadline = time.time() + float(timeout_s)
    while time.time() < deadline:
        for hwnd, title in _enum_windows_titles():
            if needle_cf and needle_cf in (title or "").casefold():
                return int(hwnd)
        time.sleep(0.25)
    return 0

def _assert_proxy_hidden_from_taskbar_if_default() -> None:
    if os.name != "nt":
        return
    if not config_path:
        return
    try:
        cfg = json.loads(open(config_path, "r", encoding="utf-8").read() or "{}")
    except Exception:
        cfg = {}

    headless_value = cfg.get("camoufox_proxy_headless", None)
    headless = bool(headless_value) if headless_value is not None else False
    if headless:
        return

    window_mode = str(cfg.get("camoufox_proxy_window_mode") or "").strip().lower()
    should_assert = (not window_mode) or (window_mode in ("hide", "hidden"))
    if not should_assert:
        return
    marker = "LMArenaBridge Camoufox Proxy"
    hwnd = _find_hwnd_by_title_substring(marker, timeout_s=90.0)
    if not hwnd:
        fail(f"Could not find proxy window title containing: {marker}")

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    GWL_EXSTYLE = -20
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_APPWINDOW = 0x00040000

    GetWindowLongW = user32.GetWindowLongW
    GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    GetWindowLongW.restype = ctypes.c_long

    deadline = time.time() + 20.0
    while time.time() < deadline:
        exstyle = int(GetWindowLongW(wintypes.HWND(hwnd), GWL_EXSTYLE) or 0)
        ok_tool = (exstyle & WS_EX_TOOLWINDOW) == WS_EX_TOOLWINDOW
        ok_app = (exstyle & WS_EX_APPWINDOW) != WS_EX_APPWINDOW
        if ok_tool and ok_app:
            return
        time.sleep(0.25)
    fail("Proxy window is still on taskbar (missing WS_EX_TOOLWINDOW and/or has WS_EX_APPWINDOW)")

with httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=True) as client:
    if include_dashboard:
        r = client.post(
            base + "/login",
            data={"password": dashboard_password},
        )
        if r.status_code != 200:
            fail(f"/login->/dashboard HTTP {r.status_code}: {r.text[:400]}")
        if "LMArena Bridge Dashboard" not in r.text:
            fail("Dashboard HTML missing expected marker")

    _assert_proxy_hidden_from_taskbar_if_default()

    r = client.get(base + "/api/v1/models", headers=headers)
    if r.status_code != 200:
        fail(f"/api/v1/models HTTP {r.status_code}: {r.text[:500]}")
    data = r.json()
    if not isinstance(data, dict) or "data" not in data:
        fail("Unexpected /api/v1/models response shape")

    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": "Reply with only the model name."},
            {"role": "user", "content": prompt},
        ],
        "stream": True,
        "stream_options": {"include_usage": True},
    }

    saw_done = False
    got_content = False
    content_accum: list[str] = []
    captured_data: list[str] = []

    stream_headers = dict(headers)
    stream_headers["Accept"] = "text/event-stream"
    with client.stream("POST", base + "/api/v1/chat/completions", json=payload, headers=stream_headers, timeout=timeout_seconds) as r2:
        if r2.status_code != 200:
            body = r2.read().decode("utf-8", errors="replace")
            fail(f"/api/v1/chat/completions HTTP {r2.status_code}: {body[:2000]}")

        for raw_line in r2.iter_lines():
            if raw_line is None:
                continue
            line = raw_line.strip()
            if not line:
                continue
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                saw_done = True
                break
            if len(captured_data) < 50:
                captured_data.append(data)
            obj = json.loads(data)
            if isinstance(obj, dict) and obj.get("error"):
                fail(f"Stream returned error payload: {json.dumps(obj.get('error'), ensure_ascii=False)[:800]}")
            choices = obj.get("choices") or []
            if not choices:
                continue
            delta = (choices[0] or {}).get("delta") or {}
            chunk = delta.get("content")
            if chunk:
                got_content = True
                content_accum.append(chunk)

    if not got_content:
        if captured_data:
            sys.stderr.write("Captured SSE data payloads (first 50):\\n")
            for item in captured_data:
                sys.stderr.write(item[:400] + "\\n")
        fail("Did not receive any delta.content chunks")
    if not saw_done:
        fail("Did not receive [DONE] sentinel")

    # Userscript proxy endpoints (should be safe even when using internal Camoufox proxy worker).
    r_poll = client.post(base + "/api/v1/userscript/poll", json={"timeout_seconds": 0}, headers=headers, timeout=10.0)
    if r_poll.status_code != 204:
        fail(f"/api/v1/userscript/poll expected 204, got {r_poll.status_code}: {r_poll.text[:200]}")

    r_push_missing = client.post(base + "/api/v1/userscript/push", json={"done": True}, headers=headers, timeout=10.0)
    if r_push_missing.status_code != 400:
        fail(f"/api/v1/userscript/push (missing job_id) expected 400, got {r_push_missing.status_code}: {r_push_missing.text[:200]}")

    r_push_unknown = client.post(base + "/api/v1/userscript/push", json={"job_id": "unknown-job", "done": True}, headers=headers, timeout=10.0)
    if r_push_unknown.status_code != 404:
        fail(f"/api/v1/userscript/push (unknown job_id) expected 404, got {r_push_unknown.status_code}: {r_push_unknown.text[:200]}")

    # Non-streaming path should still work (buffers upstream stream).
    payload2 = dict(payload)
    payload2["stream"] = False
    payload2.pop("stream_options", None)
    r3 = client.post(base + "/api/v1/chat/completions", json=payload2, headers=headers, timeout=timeout_seconds)
    if r3.status_code != 200:
        fail(f"/api/v1/chat/completions (non-stream) HTTP {r3.status_code}: {r3.text[:2000]}")
    try:
        obj3 = r3.json()
    except Exception:
        fail(f"/api/v1/chat/completions (non-stream) invalid JSON: {r3.text[:2000]}")
    try:
        choices3 = obj3.get("choices") or []
        content3 = (((choices3[0] or {}).get("message") or {}) or {}).get("content") if choices3 else ""
    except Exception:
        content3 = ""
    if not isinstance(content3, str) or not content3.strip():
        fail("Non-stream response missing choices[0].message.content")

    print("[PASS] e2e_smoke")
    print("".join(content_accum).strip())
'@ | python -
  if ($LASTEXITCODE -ne 0) {
    throw "e2e_smoke python check failed (exit code $LASTEXITCODE)"
  }

  # Optional regression guard: Turnstile click spam is covered by unit tests.
  if ($EnforceTurnstileClickGuard) {
    try {
      if (Test-Path $outLog) {
        $stdoutLines = Get-Content $outLog -ErrorAction SilentlyContinue
        $usedProxy = ($stdoutLines | Select-String -SimpleMatch -Pattern "Delegating request to Userscript Proxy").Count -gt 0
        if ($usedProxy) {
          $jobStartMatch = $stdoutLines | Select-String -SimpleMatch -Pattern "Camoufox proxy: running job" | Select-Object -First 1
          if ($null -ne $jobStartMatch -and $jobStartMatch.LineNumber -gt 0) {
            $segment = $stdoutLines[($jobStartMatch.LineNumber - 1)..($stdoutLines.Count - 1)]
          } else {
            $segment = $stdoutLines
          }
          $turnstileClicks = ($segment | Select-String -SimpleMatch -Pattern "Attempting to click Cloudflare Turnstile").Count
          if ($turnstileClicks -gt $MaxTurnstileClicks) {
            throw "Too many Turnstile click attempts during first proxy job: $turnstileClicks (max $MaxTurnstileClicks)."
          }
        }
      }
    } catch {
      throw
    }
  }

  Write-Host "[PASS] e2e_smoke.ps1"
} catch {
  Write-Host "[FAIL] e2e_smoke.ps1"

  function Redact-SecretLine {
    param([string]$Line)
    $out = [string]$Line
    $out = $out -replace 'base64-[A-Za-z0-9_-]{20,}', 'base64-<REDACTED>'
    $out = $out -replace '\bsk-[A-Za-z0-9_-]{10,}', 'sk-<REDACTED>'
    $out = $out -replace '(Saved cf_clearance token:\s*)[A-Za-z0-9_-]+', '$1<REDACTED>'
    $out = $out -replace '(cf_clearance token:\s*)[A-Za-z0-9_-]+', '$1<REDACTED>'
    return $out
  }

  if (Test-Path $errLog) {
    Write-Host "--- server stderr (tail) ---"
    Get-Content $errLog -Tail 80 -ErrorAction SilentlyContinue | ForEach-Object { Redact-SecretLine $_ }
  }
  if (Test-Path $outLog) {
    Write-Host "--- server stdout (tail) ---"
    Get-Content $outLog -Tail 80 -ErrorAction SilentlyContinue | ForEach-Object { Redact-SecretLine $_ }
  }
  throw
} finally {
  if ($proc -and -not $proc.HasExited) {
    try {
      taskkill /F /T /PID $proc.Id | Out-Null
    } catch {
      Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
  }

  # Avoid leaving tracked runtime artifacts modified.
  try { git checkout -- models.json 2>$null } catch {}

  if (-not $KeepArtifacts) {
    Remove-Item $outLog, $errLog -Force -ErrorAction SilentlyContinue
  }
}
