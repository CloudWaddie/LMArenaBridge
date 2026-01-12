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
    $proc = Start-Process -FilePath python -ArgumentList @("src/main.py") -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $outLog -RedirectStandardError $errLog
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

  @'
import json
import os
import sys

import httpx

base = os.environ["LMABRIDGE_E2E_BASEURL"]
model = os.environ.get("LMABRIDGE_E2E_MODEL", "gemini-3-pro-grounding")
prompt = os.environ.get("LMABRIDGE_E2E_PROMPT", "What model is it? Reply with only the model name.")
timeout_seconds = int(os.environ.get("LMABRIDGE_E2E_STREAM_TIMEOUT", "300") or "300")
include_dashboard = os.environ.get("LMABRIDGE_E2E_INCLUDE_DASHBOARD", "0") == "1"
dashboard_password = os.environ.get("LMABRIDGE_E2E_DASHBOARD_PASSWORD", "admin")
api_key = (os.environ.get("LMABRIDGE_E2E_API_KEY") or "").strip()

headers = {}
if api_key:
    headers["Authorization"] = f"Bearer {api_key}"

def fail(msg: str) -> None:
    raise SystemExit(msg)

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
            obj = json.loads(data)
            choices = obj.get("choices") or []
            if not choices:
                continue
            delta = (choices[0] or {}).get("delta") or {}
            chunk = delta.get("content")
            if chunk:
                got_content = True
                content_accum.append(chunk)

    if not got_content:
        fail("Did not receive any delta.content chunks")
    if not saw_done:
        fail("Did not receive [DONE] sentinel")

    print("[PASS] e2e_smoke")
    print("".join(content_accum).strip())
'@ | python -

  Write-Host "[PASS] e2e_smoke.ps1"
} catch {
  Write-Host "[FAIL] e2e_smoke.ps1"
  if (Test-Path $errLog) {
    Write-Host "--- server stderr (tail) ---"
    Get-Content $errLog -Tail 80 -ErrorAction SilentlyContinue
  }
  if (Test-Path $outLog) {
    Write-Host "--- server stdout (tail) ---"
    Get-Content $outLog -Tail 80 -ErrorAction SilentlyContinue
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
