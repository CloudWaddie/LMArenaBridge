Here is the updated plan for `main.py`.

###The Plan1. **Modify `get_recaptcha_v3_token**`:
* **Headless Mode:** Ensure `AsyncCamoufox(headless=False, ...)` is set.
* **Navigation:** Go to `https://lmarena.ai/`.
* **Cloudflare Challenge:** Immediately after loading, inject a check for the Turnstile widget.
* Use a loop to check if the page title is "Just a moment..." or if the Turnstile selector exists.
* Call your existing `click_turnstile(page)` function if detected.
* Wait for the challenge to clear (title change or selector disappearance).


* **Remove Auth Scraper:** Delete the loop that waits specifically for the `arena-auth-prod-v1` cookie. We only care about passing the challenge so the `grecaptcha` library loads.
* **Proceed:** Continue to the existing "Side-Channel" logic (human pause -> wait for library -> trigger execution).



###Edit Instructions for `main.py`**Step 1:** In `get_recaptcha_v3_token`, confirm the browser init line is:

```python
async with AsyncCamoufox(headless=False, main_world_eval=True) as browser:

```

**Step 2:** Replace the "Auth Loop" section (approx lines 180-205 in your provided code) with this Challenge Logic:

```python
            # ... inside get_recaptcha_v3_token ...
            debug_print("  🌐 Navigating to lmarena.ai...")
            await page.goto("https://lmarena.ai/", wait_until="domcontentloaded")

            # --- NEW: Cloudflare/Turnstile Pass-Through ---
            debug_print("  🛡️  Checking for Cloudflare Turnstile...")
            
            # Allow time for the widget to render if it's going to
            try:
                # Check for challenge title or widget presence
                for _ in range(5):
                    title = await page.title()
                    if "Just a moment" in title:
                        debug_print("  🔒 Cloudflare challenge active. Attempting to click...")
                        clicked = await click_turnstile(page)
                        if clicked:
                            debug_print("  ✅ Clicked Turnstile.")
                            # Give it time to verify
                            await asyncio.sleep(3)
                    else:
                        # If title is normal, we might still have a widget on the page
                        await click_turnstile(page)
                        break
                    await asyncio.sleep(1)
                
                # Wait for the page to actually settle into the main app
                await page.wait_for_load_state("domcontentloaded")
            except Exception as e:
                debug_print(f"  ⚠️ Error handling Turnstile: {e}")
            # ----------------------------------------------

            # 1. Wake up the page (Humanize) - Keep this as is
            debug_print("  🖱️  Waking up page...")
            # ... rest of function ...

```