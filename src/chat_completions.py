from __future__ import annotations

async def api_chat_completions(core, request, api_key):

    # Bind globals from the owning module (src.main) so test patch points remain stable.
    AsyncExitStack = core.AsyncExitStack
    BrowserFetchStreamResponse = core.BrowserFetchStreamResponse
    HTTPException = core.HTTPException
    HTTPStatus = core.HTTPStatus
    Optional = core.Optional
    SSE_DONE = core.SSE_DONE
    SSE_KEEPALIVE = core.SSE_KEEPALIVE
    STRICT_CHROME_FETCH_MODELS = core.STRICT_CHROME_FETCH_MODELS
    StreamingResponse = core.StreamingResponse
    _USERSCRIPT_PROXY_JOBS = core._USERSCRIPT_PROXY_JOBS
    _userscript_proxy_is_active = core._userscript_proxy_is_active
    aiter_with_keepalive = core.aiter_with_keepalive
    asyncio = core.asyncio
    chat_sessions = core.chat_sessions
    debug_print = core.debug_print
    fetch_lmarena_stream_via_camoufox = core.fetch_lmarena_stream_via_camoufox
    fetch_lmarena_stream_via_chrome = core.fetch_lmarena_stream_via_chrome
    fetch_via_proxy_queue = core.fetch_via_proxy_queue
    get_cached_recaptcha_token = core.get_cached_recaptcha_token
    get_config = core.get_config
    get_general_backoff_seconds = core.get_general_backoff_seconds
    get_models = core.get_models
    get_next_auth_token = core.get_next_auth_token
    get_rate_limit_sleep_seconds = core.get_rate_limit_sleep_seconds
    get_request_headers_with_token = core.get_request_headers_with_token
    httpx = core.httpx
    is_arena_auth_token_expired = core.is_arena_auth_token_expired
    is_probably_valid_arena_auth_token = core.is_probably_valid_arena_auth_token
    json = core.json
    last_userscript_poll = core.last_userscript_poll
    log_http_status = core.log_http_status
    maybe_refresh_expired_auth_tokens = core.maybe_refresh_expired_auth_tokens
    model_usage_stats = core.model_usage_stats
    openai_error_payload = core.openai_error_payload
    os = core.os
    print = core.print
    process_message_content = core.process_message_content
    push_proxy_chunk = core.push_proxy_chunk
    parse_lmarena_line_to_openai_chunks = core.parse_lmarena_line_to_openai_chunks
    refresh_arena_auth_token_via_lmarena_http = core.refresh_arena_auth_token_via_lmarena_http
    refresh_arena_auth_token_via_supabase = core.refresh_arena_auth_token_via_supabase
    refresh_recaptcha_token = core.refresh_recaptcha_token
    save_config = core.save_config
    sse_openai_error_and_done = core.sse_openai_error_and_done
    sse_sleep_with_keepalive = core.sse_sleep_with_keepalive
    sse_wait_for_task_with_keepalive = core.sse_wait_for_task_with_keepalive
    time = core.time
    uuid = core.uuid
    uuid7 = core.uuid7

    def format_citations(citations: list) -> tuple[list, str]:
        if not citations:
            return [], ""
        unique = []
        seen = set()
        for c in citations:
            u = c.get('url')
            if u and u not in seen:
                seen.add(u)
                unique.append(c)
        if not unique:
            return [], ""
        footnotes = "\n\n---\n\n**Sources:**\n\n"
        for i, c in enumerate(unique, 1):
            footnotes += f"{i}. [{c.get('title', 'Untitled')}]({c.get('url', '')})\n"
        return unique, footnotes

    debug_print("\n" + "="*80)
    debug_print("🔵 NEW API REQUEST RECEIVED")
    debug_print("="*80)
    
    try:
        # Parse request body with error handling
        try:
            body = await request.json()
        except json.JSONDecodeError as e:
            debug_print(f"❌ Invalid JSON in request body: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid JSON in request body: {str(e)}")
        except Exception as e:
            debug_print(f"❌ Failed to read request body: {e}")
            raise HTTPException(status_code=400, detail=f"Failed to read request body: {str(e)}")
        
        debug_print(f"📥 Request body keys: {list(body.keys())}")
        
        # Validate required fields
        model_public_name = body.get("model")
        messages = body.get("messages", [])
        stream = body.get("stream", False)
        
        debug_print(f"🌊 Stream mode: {stream}")
        debug_print(f"🤖 Requested model: {model_public_name}")
        debug_print(f"💬 Number of messages: {len(messages)}")
        
        if not model_public_name:
            debug_print("❌ Missing 'model' in request")
            raise HTTPException(status_code=400, detail="Missing 'model' in request body.")
        
        if not messages:
            debug_print("❌ Missing 'messages' in request")
            raise HTTPException(status_code=400, detail="Missing 'messages' in request body.")
        
        if not isinstance(messages, list):
            debug_print("❌ 'messages' must be an array")
            raise HTTPException(status_code=400, detail="'messages' must be an array.")
        
        if len(messages) == 0:
            debug_print("❌ 'messages' array is empty")
            raise HTTPException(status_code=400, detail="'messages' array cannot be empty.")

        # Find model ID from public name
        try:
            models = get_models()
            debug_print(f"📚 Total models loaded: {len(models)}")
        except Exception as e:
            debug_print(f"❌ Failed to load models: {e}")
            raise HTTPException(
                status_code=503,
                detail="Failed to load model list from LMArena. Please try again later."
            )
        
        model_id = None
        model_org = None
        model_capabilities = {}
        
        for m in models:
            if m.get("publicName") == model_public_name:
                model_id = m.get("id")
                model_org = m.get("organization")
                model_capabilities = m.get("capabilities", {})
                break
        
        if not model_id:
            debug_print(f"❌ Model '{model_public_name}' not found in model list")
            raise HTTPException(
                status_code=404, 
                detail=f"Model '{model_public_name}' not found. Use /api/v1/models to see available models."
            )
        
        # Check if model is a stealth model (no organization)
        if not model_org:
            debug_print(f"❌ Model '{model_public_name}' is a stealth model (no organization)")
            raise HTTPException(
                status_code=403,
                detail="You do not have access to stealth models. Contact cloudwaddie for more info."
            )
        
        debug_print(f"✅ Found model ID: {model_id}")
        debug_print(f"🔧 Model capabilities: {model_capabilities}")
        
        # Determine modality based on model capabilities.
        # Priority: image > search > chat
        if model_capabilities.get("outputCapabilities", {}).get("image"):
            modality = "image"
        elif model_capabilities.get("outputCapabilities", {}).get("search"):
            modality = "search"
        else:
            modality = "chat"
        debug_print(f"🔍 Model modality: {modality}")

        # Log usage
        try:
            model_usage_stats[model_public_name] += 1
            # Save stats immediately after incrementing
            config = get_config()
            config["usage_stats"] = dict(model_usage_stats)
            save_config(config)
        except Exception as e:
            # Don't fail the request if usage logging fails
            debug_print(f"⚠️  Failed to log usage stats: {e}")

        # Extract system prompt if present and prepend to first user message
        system_prompt = ""
        system_messages = [m for m in messages if m.get("role") == "system"]
        if system_messages:
            system_prompt = "\n\n".join([m.get("content", "") for m in system_messages])
            debug_print(f"📋 System prompt found: {system_prompt[:100]}..." if len(system_prompt) > 100 else f"📋 System prompt: {system_prompt}")
        
        # Process last message content (may include images)
        try:
            last_message_content = messages[-1].get("content", "")
            prompt, experimental_attachments = await process_message_content(last_message_content, model_capabilities)
            raw_user_prompt = prompt
            
            # If there's a system prompt and this is the first user message, prepend it
            if system_prompt:
                prompt = f"{system_prompt}\n\n{prompt}"
                debug_print(f"✅ System prompt prepended to user message")
        except Exception as e:
            debug_print(f"❌ Failed to process message content: {e}")
            raise HTTPException(
                status_code=400,
                detail=f"Failed to process message content: {str(e)}"
            )
        
        # Validate prompt
        if not prompt:
            # If no text but has attachments, that's okay for vision models
            if not experimental_attachments:
                debug_print("❌ Last message has no content")
                raise HTTPException(status_code=400, detail="Last message must have content.")
        
        # Log prompt length for debugging character limit issues
        debug_print(f"📝 User prompt length: {len(prompt)} characters")
        debug_print(f"🖼️  Attachments: {len(experimental_attachments)} images")
        debug_print(f"📝 User prompt preview: {prompt[:100]}..." if len(prompt) > 100 else f"📝 User prompt: {prompt}")
        
        # Check for reasonable character limit (LMArena appears to have limits)
        # Typical limit seems to be around 32K-64K characters based on testing
        MAX_PROMPT_LENGTH = 113567  # User hardcoded limit
        if len(prompt) > MAX_PROMPT_LENGTH:
            error_msg = f"Prompt too long ({len(prompt)} characters). LMArena has a character limit of approximately {MAX_PROMPT_LENGTH} characters. Please reduce the message size."
            debug_print(f"❌ {error_msg}")
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Use API key + conversation tracking
        api_key_str = api_key["key"]

        # --- NEW: Get reCAPTCHA v3 Token for Payload ---
        # For strict models (and web-capability models), we defer token minting to in-browser transports to avoid extra
        # automation-driven token requests (which can lower scores and increase flakiness).
        output_caps = {}
        try:
            output_caps = model_capabilities.get("outputCapabilities") if isinstance(model_capabilities, dict) else {}
        except Exception:
            output_caps = {}
        if not isinstance(output_caps, dict):
            output_caps = {}
        web_capability_model = bool(output_caps.get("web"))

        use_chrome_fetch_for_model = (model_public_name in STRICT_CHROME_FETCH_MODELS) or web_capability_model
        strict_chrome_fetch_model = use_chrome_fetch_for_model

        recaptcha_token = ""
        if strict_chrome_fetch_model:
            if web_capability_model and (model_public_name not in STRICT_CHROME_FETCH_MODELS):
                debug_print(f"🔐 Web-capability model detected ({model_public_name}), enabling browser transports.")
            # If the internal proxy is active, we MUST NOT use a cached token, as it causes 403s.
            # Instead, we pass an empty string and let the in-page minting handle it.
            if (time.time() - last_userscript_poll) < 15:
                debug_print("🔐 Strict model + Proxy: token will be minted in-page.")
                recaptcha_token = ""
            else:
                # Best-effort: use a cached token so browser transports don't have to wait on grecaptcha to load.
                # (They can still mint in-session if needed.)
                recaptcha_token = get_cached_recaptcha_token()
                if recaptcha_token:
                    debug_print("🔐 Strict model: using cached reCAPTCHA v3 token in payload.")
                else:
                    debug_print("🔐 Strict model: reCAPTCHA token will be minted in the Chrome fetch session.")
        else:
            # Proxy-only transport: reCAPTCHA tokens are minted in-page by the Userscript Proxy.
            recaptcha_token = ""
        # -----------------------------------------------
        
        # Generate conversation ID from context (API key + model + first user message)
        import hashlib
        first_user_message = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
        if isinstance(first_user_message, list):
            # Handle array content format
            first_user_message = str(first_user_message)
        conversation_key = f"{api_key_str}_{model_public_name}_{first_user_message[:100]}"
        conversation_id = hashlib.sha256(conversation_key.encode()).hexdigest()[:16]
        
        debug_print(f"🔑 API Key: {api_key_str[:20]}...")
        debug_print(f"💭 Auto-generated Conversation ID: {conversation_id}")
        debug_print(f"🔑 Conversation key: {conversation_key[:100]}...")

        # Headers are prepared after selecting an auth token (or when falling back to browser-only transports).
        headers: dict[str, str] = {}
        
        # Check if conversation exists for this API key (robust to tests patching chat_sessions to a plain dict)
        per_key_sessions = chat_sessions.setdefault(api_key_str, {})
        session = per_key_sessions.get(conversation_id)
        
        # Detect retry: if session exists and last message is same user message (no assistant response after it)
        is_retry = False
        retry_message_id = None
        
        if session and len(session.get("messages", [])) >= 2:
            stored_messages = session["messages"]
            # Check if last stored message is from user with same content
            if stored_messages[-1]["role"] == "user" and stored_messages[-1]["content"] == prompt:
                # This is a retry - client sent same message again without assistant response
                is_retry = True
                retry_message_id = stored_messages[-1]["id"]
                # Get the assistant message ID that needs to be regenerated
                if len(stored_messages) >= 2 and stored_messages[-2]["role"] == "assistant":
                    # There was a previous assistant response - we'll retry that one
                    retry_message_id = stored_messages[-2]["id"]
                    debug_print(f"🔁 RETRY DETECTED - Regenerating assistant message {retry_message_id}")
        
        if is_retry and retry_message_id:
            debug_print(f"🔁 Using RETRY endpoint")
            # Use LMArena's retry endpoint
            # Format: PUT /nextjs-api/stream/retry-evaluation-session-message/{sessionId}/messages/{messageId}
            payload = {}
            url = f"https://lmarena.ai/nextjs-api/stream/retry-evaluation-session-message/{session['conversation_id']}/messages/{retry_message_id}"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Using PUT method for retry")
            http_method = "PUT"
        elif not session:
            debug_print("🆕 Creating NEW conversation session")
            outbound_prompt = prompt

            # If the bridge has no in-memory session (e.g. after restart) but the client provided prior turns,
            # embed the transcript into the first outbound prompt so the model can answer consistently.
            try:
                has_prior_turns = any(
                    (m.get("role") in ("user", "assistant"))
                    for m in (messages[:-1] or [])
                    if (m.get("role") != "system")
                )
            except Exception:
                has_prior_turns = False

            if has_prior_turns and not experimental_attachments:
                def _stringify_transcript_content(value: object) -> str:
                    if isinstance(value, str):
                        return value
                    if isinstance(value, list):
                        parts: list[str] = []
                        for item in value:
                            if not isinstance(item, dict):
                                continue
                            if item.get("type") == "text" and isinstance(item.get("text"), str):
                                parts.append(item.get("text") or "")
                            elif item.get("type") == "image_url":
                                parts.append("[image]")
                            elif isinstance(item.get("text"), str):
                                parts.append(item.get("text") or "")
                        merged = "\n".join([p for p in parts if str(p or "").strip()])
                        if merged:
                            return merged
                    try:
                        return json.dumps(value, ensure_ascii=False)
                    except Exception:
                        return str(value)

                non_system_messages = [m for m in (messages or []) if m.get("role") != "system"]
                # Keep the transcript bounded to avoid hitting LMArena prompt limits on long chats.
                if len(non_system_messages) > 20:
                    non_system_messages = non_system_messages[-20:]

                transcript_blocks: list[str] = []
                last_index = len(non_system_messages) - 1
                for idx, msg in enumerate(non_system_messages):
                    role = str(msg.get("role") or "").strip().lower()
                    if role == "user" and idx == last_index:
                        content = raw_user_prompt
                    else:
                        content = _stringify_transcript_content(msg.get("content", ""))
                    content = str(content or "").strip()
                    if not content:
                        continue
                    label = "User" if role == "user" else "Assistant" if role == "assistant" else (role or "Message")
                    transcript_blocks.append(f"{label}:\n{content}")

                if transcript_blocks:
                    outbound_prompt = "Conversation transcript:\n\n" + "\n\n".join(transcript_blocks)
                    if system_prompt:
                        outbound_prompt = f"{system_prompt}\n\n{outbound_prompt}"
                    # Re-validate length with transcript expansion.
                    if len(outbound_prompt) > 113567:
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                f"Prompt too long ({len(outbound_prompt)} characters) after including chat history. "
                                "Please reduce the message size."
                            ),
                        )
                    debug_print("⚠️ No in-memory session; embedding provided message history into prompt.")
            # New conversation - Generate all IDs at once (like the browser does)
            session_id = str(uuid7())
            user_msg_id = str(uuid7())
            model_msg_id = str(uuid7())
            model_b_msg_id = str(uuid7())
            
            debug_print(f"🔑 Generated session_id: {session_id}")
            debug_print(f"👤 Generated user_msg_id: {user_msg_id}")
            debug_print(f"🤖 Generated model_msg_id: {model_msg_id}")
            debug_print(f"🤖 Generated model_b_msg_id: {model_b_msg_id}")
             
            payload = {
                "id": session_id,
                "mode": "direct",
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "modelBMessageId": model_b_msg_id,
                "userMessage": {
                    "content": outbound_prompt,
                    "experimental_attachments": experimental_attachments,
                    "metadata": {}
                },
                "modality": modality,
                "recaptchaV3Token": recaptcha_token, # <--- ADD TOKEN HERE
            }
            url = "https://lmarena.ai/nextjs-api/stream/create-evaluation"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Payload structure: Simple userMessage format")
            debug_print(f"🔍 Full payload: {json.dumps(payload, indent=2)}")
            http_method = "POST"
        else:
            debug_print("🔄 Using EXISTING conversation session")
            # Follow-up message - Generate new message IDs
            user_msg_id = str(uuid7())
            debug_print(f"👤 Generated followup user_msg_id: {user_msg_id}")
            model_msg_id = str(uuid7())
            debug_print(f"🤖 Generated followup model_msg_id: {model_msg_id}")
            model_b_msg_id = str(uuid7())
            debug_print(f"🤖 Generated followup model_b_msg_id: {model_b_msg_id}")
             
            payload = {
                "id": session["conversation_id"],
                "modelAId": model_id,
                "userMessageId": user_msg_id,
                "modelAMessageId": model_msg_id,
                "modelBMessageId": model_b_msg_id,
                "userMessage": {
                    "content": prompt,
                    "experimental_attachments": experimental_attachments,
                    "metadata": {}
                },
                "modality": modality,
                "recaptchaV3Token": recaptcha_token, # <--- ADD TOKEN HERE
            }
            url = f"https://lmarena.ai/nextjs-api/stream/post-to-evaluation/{session['conversation_id']}"
            debug_print(f"📤 Target URL: {url}")
            debug_print(f"📦 Payload structure: Simple userMessage format")
            debug_print(f"🔍 Full payload: {json.dumps(payload, indent=2)}")
            http_method = "POST"

        debug_print(f"\n🚀 Making API request to LMArena...")
        debug_print(f"⏱️  Timeout set to: 120 seconds")
        
        # Initialize failed tokens tracking for this request
        request_id = str(uuid.uuid4())
        failed_tokens = set()
        
        # Get initial auth token using round-robin (excluding any failed ones)
        current_token = ""
        try:
            current_token = get_next_auth_token(exclude_tokens=failed_tokens)
        except HTTPException:
            # Proxy-only: requests can proceed via the in-browser session cookie (anonymous or authenticated).
            debug_print("⚠️ No auth token configured; proceeding with Userscript Proxy only.")
            current_token = ""

        # Strict models: if round-robin picked a placeholder/invalid-looking token but there is a better token
        # available, switch to the first plausible token without mutating user config.
        if strict_chrome_fetch_model and current_token and not is_probably_valid_arena_auth_token(current_token):
            try:
                cfg_now = get_config()
                tokens_now = cfg_now.get("auth_tokens", [])
                if not isinstance(tokens_now, list):
                    tokens_now = []
            except Exception:
                tokens_now = []
            better = ""
            for cand in tokens_now:
                cand = str(cand or "").strip()
                if not cand or cand == current_token or cand in failed_tokens:
                    continue
                if is_probably_valid_arena_auth_token(cand):
                    better = cand
                    break
            if better:
                debug_print("🔑 Switching to a plausible auth token for strict model streaming.")
                current_token = better
            else:
                debug_print("⚠️ Selected auth token format looks unusual; continuing with it (no better token found).")

        # If we still don't have a usable token (e.g. only expired base64 sessions remain), try to refresh one
        # in-memory only (do not rewrite the user's config.json auth tokens).
        if (not current_token) or (not is_probably_valid_arena_auth_token(current_token)):
            try:
                refreshed = await maybe_refresh_expired_auth_tokens(exclude_tokens=failed_tokens)
            except Exception:
                refreshed = None
            if refreshed:
                debug_print("🔄 Refreshed arena-auth-prod-v1 session.")
                current_token = refreshed
            # Strict models can operate purely from the browser session cookie; do not send obviously-expired
            # tokens (they cause immediate 401s and prevent the proxy from minting a fresh anonymous session).
            if strict_chrome_fetch_model and current_token and not is_probably_valid_arena_auth_token(current_token):
                current_token = ""
        headers = get_request_headers_with_token(current_token, recaptcha_token)
        if current_token:
            debug_print(f"🔑 Using token (round-robin): {current_token[:20]}...")
        else:
            debug_print("🔑 No auth token configured (will rely on browser session cookies).")
        
        # Retry logic wrapper
        async def make_request_with_retry(url, payload, http_method, max_retries=3):
            """Make request with automatic retry on 429/401 errors"""
            nonlocal current_token, headers, failed_tokens, recaptcha_token
            
            for attempt in range(max_retries):
                try:
                    async with httpx.AsyncClient() as client:
                        if http_method == "PUT":
                            response = await client.put(url, json=payload, headers=headers, timeout=120)
                        else:
                            response = await client.post(url, json=payload, headers=headers, timeout=120)
                        
                        # Log status with human-readable message
                        log_http_status(response.status_code, "LMArena API")
                        
                        # Check for retry-able errors
                        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                            debug_print(f"⏱️  Attempt {attempt + 1}/{max_retries} - Rate limit with token {current_token[:20]}...")
                            retry_after = response.headers.get("Retry-After")
                            sleep_seconds = get_rate_limit_sleep_seconds(retry_after, attempt)
                            debug_print(f"  Retry-After header: {retry_after!r}")
                            
                            if attempt < max_retries - 1:
                                try:
                                    # Try with next token (excluding failed ones)
                                    current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                    headers = get_request_headers_with_token(current_token, recaptcha_token)
                                    debug_print(f"🔄 Retrying with next token: {current_token[:20]}...")
                                    await asyncio.sleep(sleep_seconds)
                                    continue
                                except HTTPException as e:
                                    debug_print(f"❌ No more tokens available: {e.detail}")
                                    break
                        
                        elif response.status_code == HTTPStatus.FORBIDDEN:
                            try:
                                error_body = response.json()
                            except Exception:
                                error_body = None
                            if isinstance(error_body, dict) and error_body.get("error") == "recaptcha validation failed":
                                debug_print(
                                    f"🤖 Attempt {attempt + 1}/{max_retries} - reCAPTCHA validation failed. Refreshing token..."
                                )
                                new_token = await refresh_recaptcha_token(force_new=True)
                                if new_token and isinstance(payload, dict):
                                    payload["recaptchaV3Token"] = new_token
                                    recaptcha_token = new_token
                                if attempt < max_retries - 1:
                                    headers = get_request_headers_with_token(current_token, recaptcha_token)
                                    await asyncio.sleep(1)
                                    continue

                        elif response.status_code == HTTPStatus.UNAUTHORIZED:
                            debug_print(f"🔒 Attempt {attempt + 1}/{max_retries} - Auth failed with token {current_token[:20]}...")
                            # Add current token to failed set
                            failed_tokens.add(current_token)
                            # (Pruning disabled)
                            debug_print(f"📝 Failed tokens so far: {len(failed_tokens)}")
                            
                            if attempt < max_retries - 1:
                                try:
                                    # Try with next available token (excluding failed ones)
                                    current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                    headers = get_request_headers_with_token(current_token, recaptcha_token)
                                    debug_print(f"🔄 Retrying with next token: {current_token[:20]}...")
                                    await asyncio.sleep(1)  # Brief delay
                                    continue
                                except HTTPException as e:
                                    debug_print(f"❌ No more tokens available: {e.detail}")
                                    break
                        
                        # If we get here, return the response (success or non-retryable error)
                        response.raise_for_status()
                        return response
                        
                except httpx.HTTPStatusError as e:
                    # Only handle 429 and 401, let other errors through
                    if e.response.status_code not in [429, 401]:
                        raise
                    # If last attempt, raise the error
                    if attempt == max_retries - 1:
                        raise
            
            # Should not reach here, but just in case
            raise HTTPException(status_code=503, detail="Max retries exceeded")
        
        # Handle streaming mode
        if stream:
            async def generate_stream():
                nonlocal current_token, headers, failed_tokens, recaptcha_token
                
                # Safety: don't keep client sockets open forever on repeated upstream failures.
                try:
                    stream_total_timeout_seconds = float(get_config().get("stream_total_timeout_seconds", 600))
                except Exception:
                    stream_total_timeout_seconds = 600.0
                stream_total_timeout_seconds = max(30.0, min(stream_total_timeout_seconds, 3600.0))
                stream_started_at = time.monotonic()

                # Flush an immediate comment to keep the client connection alive while we do heavy lifting upstream
                yield SSE_KEEPALIVE
                await asyncio.sleep(0)

                chunk_id = f"chatcmpl-{uuid.uuid4()}"

                # Proxy-only transport: always mint reCAPTCHA tokens in-page via the Userscript Proxy.
                # (Side-channel tokens + direct httpx have proven unreliable and are intentionally disabled.)
                use_browser_transports = False
                prefer_chrome_transport = False
                recaptcha_token = ""
                if isinstance(payload, dict):
                    payload["recaptchaV3Token"] = ""
                headers = get_request_headers_with_token(current_token, recaptcha_token)
                
                recaptcha_403_failures = 0
                no_delta_failures = 0
                attempt = 0
                recaptcha_403_consecutive = 0
                recaptcha_403_last_transport: Optional[str] = None
                strict_token_prefill_attempted = False
                disable_userscript_for_request = False
                force_proxy_recaptcha_mint = False
                disable_userscript_proxy_env = bool(os.environ.get("LM_BRIDGE_DISABLE_USERSCRIPT_PROXY"))

                retry_429_count = 0
                retry_403_count = 0

                max_retries = 3
                current_retry_attempt = 0
                
                # Infinite retry loop (until client disconnects, max attempts reached, or we get success)
                while True:
                    attempt += 1

                    # Abort if the client disconnects.
                    try:
                        if await request.is_disconnected():
                            return
                    except Exception:
                        pass

                    # Stop retrying after a configurable deadline or too many attempts to avoid infinite hangs.
                    if (time.monotonic() - stream_started_at) > stream_total_timeout_seconds or attempt > 20:
                        yield f"data: {json.dumps(openai_error_payload('Upstream retry timeout or max attempts exceeded while streaming from LMArena.', 'upstream_timeout', HTTPStatus.GATEWAY_TIMEOUT))}\n\n"
                        yield SSE_DONE
                        return
                    # Reset response data for each attempt
                    response_text = ""
                    reasoning_text = ""
                    citations = []
                    unhandled_preview: list[str] = []

                    try:
                        async with AsyncExitStack() as stack:
                            debug_print(f"📡 Sending {http_method} request for streaming (attempt {attempt})...")
                            stream_context = None
                            transport_used = "httpx"
                            
                            # Userscript Proxy is the only supported transport for upstream requests.
                            use_userscript = False
                            cfg_now = None
                            if not disable_userscript_proxy_env:
                                try:
                                    cfg_now = get_config()
                                except Exception:
                                    cfg_now = None

                                try:
                                    proxy_active = _userscript_proxy_is_active(cfg_now)
                                except Exception:
                                    proxy_active = False

                                if not proxy_active:
                                    try:
                                        grace_seconds = float((cfg_now or {}).get("userscript_proxy_grace_seconds", 0.5))
                                    except Exception:
                                        grace_seconds = 0.5
                                    grace_seconds = max(0.0, min(grace_seconds, 2.0))
                                    if grace_seconds > 0:
                                        deadline = time.time() + grace_seconds
                                        while time.time() < deadline:
                                            try:
                                                if _userscript_proxy_is_active(cfg_now):
                                                    proxy_active = True
                                                    break
                                            except Exception:
                                                pass
                                            yield SSE_KEEPALIVE
                                            await asyncio.sleep(0.05)

                                use_userscript = bool(proxy_active)

                            if not use_userscript:
                                yield f"data: {json.dumps(openai_error_payload('Userscript proxy is required for streaming. Start the Camoufox proxy worker/userscript bridge and retry.', 'proxy_unavailable', HTTPStatus.SERVICE_UNAVAILABLE))}\n\n"
                                yield SSE_DONE
                                return

                            debug_print("🌐 Userscript Proxy is ACTIVE. Using Userscript Proxy for streaming.")
                            debug_print(
                                f"📫 Delegating request to Userscript Proxy (poll active {int(time.time() - last_userscript_poll)}s ago)..."
                            )
                            proxy_auth_token = str(current_token or "").strip()
                            try:
                                # Preserve expired base64 Supabase session cookies: they can often be refreshed
                                # in-page via their embedded refresh_token (no user interaction).
                                if (
                                    proxy_auth_token
                                    and not str(proxy_auth_token).startswith("base64-")
                                    and is_arena_auth_token_expired(proxy_auth_token, skew_seconds=0)
                                ):
                                    proxy_auth_token = ""
                            except Exception:
                                pass
                            stream_context = await fetch_via_proxy_queue(
                                url=url,
                                payload=payload if isinstance(payload, dict) else {},
                                http_method=http_method,
                                timeout_seconds=300,
                                streaming=True,
                                auth_token=proxy_auth_token,
                            )
                            if stream_context is None:
                                yield f"data: {json.dumps(openai_error_payload('Userscript proxy request timed out or returned no response.', 'proxy_timeout', HTTPStatus.GATEWAY_TIMEOUT))}\n\n"
                                yield SSE_DONE
                                return

                            transport_used = "userscript"

                            # Strict models: when we're about to fall back to buffered browser fetch transports (not the
                            # streaming proxy), a side-channel token can avoid hangs while grecaptcha loads in-page.
                            if (
                                stream_context is None
                                and use_browser_transports
                                and not use_userscript
                                and isinstance(payload, dict)
                                and not strict_token_prefill_attempted
                                and not str(payload.get("recaptchaV3Token") or "").strip()
                            ):
                                strict_token_prefill_attempted = True
                                try:
                                    refresh_task = asyncio.create_task(refresh_recaptcha_token(force_new=True))
                                except Exception:
                                    refresh_task = None
                                if refresh_task is not None:
                                    while True:
                                        done, _ = await asyncio.wait({refresh_task}, timeout=1.0)
                                        if refresh_task in done:
                                            break
                                        yield SSE_KEEPALIVE
                                    try:
                                        new_token = refresh_task.result()
                                    except Exception:
                                        new_token = None
                                    if new_token:
                                        payload["recaptchaV3Token"] = new_token

                            if stream_context is None and use_browser_transports:
                                browser_fetch_attempts = 5
                                try:
                                    browser_fetch_attempts = int(get_config().get("chrome_fetch_recaptcha_max_attempts", 5))
                                except Exception:
                                    browser_fetch_attempts = 5

                                # If we have a cached side-channel reCAPTCHA token, prefer passing it into the browser
                                # fetch transports (they will reuse it on the first attempt and only mint in-page if
                                # needed). This helps when in-page grecaptcha is slow/flaky.
                                if isinstance(payload, dict) and not str(payload.get("recaptchaV3Token") or "").strip():
                                    try:
                                        cached_token = get_cached_recaptcha_token()
                                    except Exception:
                                        cached_token = ""
                                    if cached_token:
                                        payload["recaptchaV3Token"] = cached_token

                                async def _try_chrome_fetch() -> Optional[BrowserFetchStreamResponse]:
                                    debug_print("🌐 Using Chrome fetch transport for streaming...")
                                    try:
                                        auth_for_browser = str(current_token or "").strip()
                                        try:
                                            cand = str(core.EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
                                        except Exception:
                                            cand = ""
                                        if cand:
                                            try:
                                                if (
                                                    is_probably_valid_arena_auth_token(cand)
                                                    and not is_arena_auth_token_expired(cand, skew_seconds=0)
                                                    and (
                                                        (not auth_for_browser)
                                                        or (not is_probably_valid_arena_auth_token(auth_for_browser))
                                                        or is_arena_auth_token_expired(auth_for_browser, skew_seconds=0)
                                                    )
                                                ):
                                                    auth_for_browser = cand
                                            except Exception:
                                                auth_for_browser = cand

                                        try:
                                            chrome_outer_timeout = float(get_config().get("chrome_fetch_outer_timeout_seconds", 120))
                                        except Exception:
                                            chrome_outer_timeout = 120.0
                                        chrome_outer_timeout = max(20.0, min(chrome_outer_timeout, 300.0))

                                        return await asyncio.wait_for(
                                            fetch_lmarena_stream_via_chrome(
                                                http_method=http_method,
                                                url=url,
                                                payload=payload if isinstance(payload, dict) else {},
                                                auth_token=auth_for_browser,
                                                timeout_seconds=120,
                                                max_recaptcha_attempts=browser_fetch_attempts,
                                            ),
                                            timeout=chrome_outer_timeout,
                                        )
                                    except asyncio.TimeoutError:
                                        debug_print("⚠️ Chrome fetch transport timed out (launch/nav hang).")
                                        return None
                                    except Exception as e:
                                        debug_print(f"⚠️ Chrome fetch transport error: {e}")
                                        return None

                                async def _try_camoufox_fetch() -> Optional[BrowserFetchStreamResponse]:
                                    debug_print("🦊 Using Camoufox fetch transport for streaming...")
                                    try:
                                        auth_for_browser = str(current_token or "").strip()
                                        try:
                                            cand = str(core.EPHEMERAL_ARENA_AUTH_TOKEN or "").strip()
                                        except Exception:
                                            cand = ""
                                        if cand:
                                            try:
                                                if (
                                                    is_probably_valid_arena_auth_token(cand)
                                                    and not is_arena_auth_token_expired(cand, skew_seconds=0)
                                                    and (
                                                        (not auth_for_browser)
                                                        or (not is_probably_valid_arena_auth_token(auth_for_browser))
                                                        or is_arena_auth_token_expired(auth_for_browser, skew_seconds=0)
                                                    )
                                                ):
                                                    auth_for_browser = cand
                                            except Exception:
                                                auth_for_browser = cand

                                        try:
                                            camoufox_outer_timeout = float(
                                                get_config().get("camoufox_fetch_outer_timeout_seconds", 180)
                                            )
                                        except Exception:
                                            camoufox_outer_timeout = 180.0
                                        camoufox_outer_timeout = max(20.0, min(camoufox_outer_timeout, 300.0))

                                        return await asyncio.wait_for(
                                            fetch_lmarena_stream_via_camoufox(
                                                http_method=http_method,
                                                url=url,
                                                payload=payload if isinstance(payload, dict) else {},
                                                auth_token=auth_for_browser,
                                                timeout_seconds=120,
                                                max_recaptcha_attempts=browser_fetch_attempts,
                                            ),
                                            timeout=camoufox_outer_timeout,
                                        )
                                    except asyncio.TimeoutError:
                                        debug_print("⚠️ Camoufox fetch transport timed out (launch/nav hang).")
                                        return None
                                    except Exception as e:
                                        debug_print(f"⚠️ Camoufox fetch transport error: {e}")
                                        return None

                                if prefer_chrome_transport:
                                    chrome_task = asyncio.create_task(_try_chrome_fetch())
                                    while True:
                                        done, _ = await asyncio.wait({chrome_task}, timeout=1.0)
                                        if chrome_task in done:
                                            try:
                                                stream_context = chrome_task.result()
                                            except Exception:
                                                stream_context = None
                                            break
                                        yield SSE_KEEPALIVE
                                    if stream_context is not None:
                                        transport_used = "chrome"
                                    if stream_context is None:
                                        camoufox_task = asyncio.create_task(_try_camoufox_fetch())
                                        while True:
                                            done, _ = await asyncio.wait({camoufox_task}, timeout=1.0)
                                            if camoufox_task in done:
                                                try:
                                                    stream_context = camoufox_task.result()
                                                except Exception:
                                                    stream_context = None
                                                break
                                            yield SSE_KEEPALIVE
                                        if stream_context is not None:
                                            transport_used = "camoufox"
                                else:
                                    camoufox_task = asyncio.create_task(_try_camoufox_fetch())
                                    while True:
                                        done, _ = await asyncio.wait({camoufox_task}, timeout=1.0)
                                        if camoufox_task in done:
                                            try:
                                                stream_context = camoufox_task.result()
                                            except Exception:
                                                stream_context = None
                                            break
                                        yield SSE_KEEPALIVE
                                    if stream_context is not None:
                                        transport_used = "camoufox"
                                    if stream_context is None:
                                        chrome_task = asyncio.create_task(_try_chrome_fetch())
                                        while True:
                                            done, _ = await asyncio.wait({chrome_task}, timeout=1.0)
                                            if chrome_task in done:
                                                try:
                                                    stream_context = chrome_task.result()
                                                except Exception:
                                                    stream_context = None
                                                break
                                            yield SSE_KEEPALIVE
                                        if stream_context is not None:
                                            transport_used = "chrome"

                            if stream_context is None:
                                client = await stack.enter_async_context(httpx.AsyncClient())
                                if http_method == "PUT":
                                    stream_context = client.stream('PUT', url, json=payload, headers=headers, timeout=120)
                                else:
                                    stream_context = client.stream('POST', url, json=payload, headers=headers, timeout=120)
                                transport_used = "httpx"

                            # Userscript proxy jobs report their upstream HTTP status asynchronously.
                            # Wait for the status (or completion) before branching on status_code, while still
                            # keeping the client connection alive.
                            if transport_used == "userscript":
                                proxy_job_id = ""
                                try:
                                    proxy_job_id = str(getattr(stream_context, "job_id", "") or "").strip()
                                except Exception:
                                    proxy_job_id = ""

                                proxy_job = _USERSCRIPT_PROXY_JOBS.get(proxy_job_id) if proxy_job_id else None
                                status_event = None
                                done_event = None
                                picked_up_event = None
                                if isinstance(proxy_job, dict):
                                    status_event = proxy_job.get("status_event")
                                    done_event = proxy_job.get("done_event")
                                    picked_up_event = proxy_job.get("picked_up_event")
 
                                if isinstance(status_event, asyncio.Event) and not status_event.is_set():
                                    try:
                                        pickup_timeout_seconds = float(
                                            get_config().get("userscript_proxy_pickup_timeout_seconds", 10)
                                        )
                                    except Exception:
                                        pickup_timeout_seconds = 10.0
                                    pickup_timeout_seconds = max(0.5, min(pickup_timeout_seconds, 15.0))

                                    try:
                                        proxy_status_timeout_seconds = float(
                                            get_config().get("userscript_proxy_status_timeout_seconds", 180)
                                        )
                                    except Exception:
                                        proxy_status_timeout_seconds = 180.0
                                    proxy_status_timeout_seconds = max(5.0, min(proxy_status_timeout_seconds, 300.0))
 
                                    started = time.monotonic()
                                    proxy_status_timed_out = False
                                    while not status_event.is_set():
                                        if isinstance(done_event, asyncio.Event) and done_event.is_set():
                                            break
                                        elapsed = time.monotonic() - started
                                        picked_up = True
                                        if isinstance(picked_up_event, asyncio.Event):
                                            picked_up = bool(picked_up_event.is_set())

                                        if (not picked_up) and elapsed >= pickup_timeout_seconds:
                                            debug_print(
                                                f"⚠️ Userscript proxy did not pick up job within {int(pickup_timeout_seconds)}s."
                                            )
                                            disable_userscript_for_request = True
                                            try:
                                                await push_proxy_chunk(
                                                    proxy_job_id,
                                                    {"error": "userscript proxy pickup timeout", "done": True},
                                                )
                                            except Exception:
                                                pass
                                            # Prevent the internal proxy worker from doing wasted work on a job we
                                            # already declared dead.
                                            try:
                                                _USERSCRIPT_PROXY_JOBS.pop(proxy_job_id, None)
                                            except Exception:
                                                pass
                                            proxy_status_timed_out = True
                                            break

                                        if picked_up and elapsed >= proxy_status_timeout_seconds:
                                            debug_print(
                                                f"⚠️ Userscript proxy did not report upstream status within {int(proxy_status_timeout_seconds)}s."
                                            )
                                            # Treat the proxy as unavailable for the rest of this request and fall back
                                            # to other transports (Chrome/Camoufox/httpx). Otherwise we'd keep queuing
                                            # jobs that will never be picked up and stall for a long time.
                                            disable_userscript_for_request = True
                                            try:
                                                await push_proxy_chunk(
                                                    proxy_job_id,
                                                    {"error": "userscript proxy status timeout", "done": True},
                                                )
                                            except Exception:
                                                pass
                                            proxy_status_timed_out = True
                                            break
 
                                        yield SSE_KEEPALIVE
                                        await asyncio.sleep(1.0)

                                    if proxy_status_timed_out:
                                        async for ka in sse_sleep_with_keepalive(core, 0.5):
                                            yield ka
                                        continue
                            
                            async with stream_context as response:
                                # Log status with human-readable message
                                log_http_status(response.status_code, "LMArena API Stream")
                                
                                # Check for retry-able errors before processing stream
                                if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                                    retry_429_count += 1
                                    if retry_429_count > 3:
                                        yield f"data: {json.dumps(openai_error_payload('Too Many Requests (429) from upstream. Retries exhausted.', 'rate_limit_error', HTTPStatus.TOO_MANY_REQUESTS))}\n\n"
                                        yield SSE_DONE
                                        return

                                    retry_after = None
                                    try:
                                        retry_after = response.headers.get("Retry-After")
                                    except Exception:
                                        retry_after = None
                                    if not retry_after:
                                        try:
                                            retry_after = response.headers.get("retry-after")
                                        except Exception:
                                            retry_after = None
                                    retry_after_value = 0.0
                                    if isinstance(retry_after, str):
                                        try:
                                            retry_after_value = float(retry_after.strip())
                                        except Exception:
                                            retry_after_value = 0.0
                                    sleep_seconds = get_rate_limit_sleep_seconds(retry_after, attempt)
                                    
                                    debug_print(
                                        f"⏱️  Stream attempt {attempt} - Upstream rate limited. Waiting {sleep_seconds}s..."
                                    )
                                    
                                    # Rotate token on rate limit to avoid spinning on the same blocked account.
                                    old_token = current_token
                                    token_rotated = False
                                    if current_token:
                                        try:
                                            rotation_exclude = set(failed_tokens)
                                            rotation_exclude.add(current_token)
                                            current_token = get_next_auth_token(
                                                exclude_tokens=rotation_exclude, allow_ephemeral_fallback=False
                                            )
                                            headers = get_request_headers_with_token(current_token, recaptcha_token)
                                            token_rotated = True
                                            debug_print(f"🔄 Retrying stream with next token: {current_token[:20]}...")
                                        except HTTPException:
                                            # Only one token (or all tokens excluded). Keep the current token and retry
                                            # after backoff instead of failing fast.
                                            debug_print("⚠️ No alternative token available; retrying with same token after backoff.")

                                    # reCAPTCHA v3 tokens can be single-use and may expire while we back off.
                                    # Clear it so the next browser fetch attempt mints a fresh token.
                                    if isinstance(payload, dict):
                                        payload["recaptchaV3Token"] = ""

                                    # If we rotated tokens, allow a fast retry when the backoff would exceed the remaining
                                    # stream deadline (common when one token is rate-limited but another isn't).
                                    if token_rotated and current_token and current_token != old_token:
                                        remaining_budget = float(stream_total_timeout_seconds) - float(
                                            time.monotonic() - stream_started_at
                                        )
                                        if float(sleep_seconds) > max(0.0, remaining_budget):
                                            sleep_seconds = min(float(sleep_seconds), 1.0)
                                    
                                    async for ka in sse_sleep_with_keepalive(core, sleep_seconds):
                                        yield ka
                                    continue
                                
                                elif response.status_code == HTTPStatus.FORBIDDEN:
                                    # Userscript proxy note:
                                    # The in-page fetch script can report an initial 403 while it mints/retries
                                    # reCAPTCHA (v3 retry + v2 fallback) and may later update the status to 200
                                    # without needing a new proxy job.
                                    if transport_used == "userscript":
                                        proxy_job_id = ""
                                        try:
                                            proxy_job_id = str(getattr(stream_context, "job_id", "") or "").strip()
                                        except Exception:
                                            proxy_job_id = ""

                                        proxy_job = _USERSCRIPT_PROXY_JOBS.get(proxy_job_id) if proxy_job_id else None
                                        proxy_done_event = None
                                        if isinstance(proxy_job, dict):
                                            proxy_done_event = proxy_job.get("done_event")

                                        # Give the proxy a chance to finish its in-page reCAPTCHA retry path before we
                                        # abandon this response and queue a new job (which can lead to pickup timeouts).
                                        try:
                                            grace_seconds = float(
                                                get_config().get("userscript_proxy_recaptcha_grace_seconds", 25)
                                            )
                                        except Exception:
                                            grace_seconds = 25.0
                                        grace_seconds = max(0.0, min(grace_seconds, 90.0))

                                        if (
                                            grace_seconds > 0.0
                                            and isinstance(proxy_done_event, asyncio.Event)
                                            and not proxy_done_event.is_set()
                                        ):
                                            # Important: do not enqueue a new proxy job while the current one is still
                                            # running. The internal Camoufox worker is single-threaded and will not pick
                                            # up new jobs until `page.evaluate()` returns.
                                            remaining_budget = float(stream_total_timeout_seconds) - float(
                                                time.monotonic() - stream_started_at
                                            )
                                            remaining_budget = max(0.0, remaining_budget)
                                            max_wait_seconds = min(max(float(grace_seconds), 200.0), remaining_budget)

                                            debug_print(
                                                f"⏳ Userscript proxy reported 403. Waiting up to {int(max_wait_seconds)}s for in-page retry..."
                                            )
                                            started = time.monotonic()
                                            warned_extended = False
                                            while (time.monotonic() - started) < float(max_wait_seconds):
                                                if response.status_code != HTTPStatus.FORBIDDEN:
                                                    debug_print(
                                                        f"✅ Userscript proxy recovered from 403 (status: {response.status_code})."
                                                    )
                                                    break
                                                if proxy_done_event.is_set():
                                                    break
                                                # If the proxy job already has an error, don't wait the full window.
                                                try:
                                                    if isinstance(proxy_job, dict) and proxy_job.get("error"):
                                                        break
                                                except Exception:
                                                    pass
                                                if (not warned_extended) and (time.monotonic() - started) >= float(
                                                    grace_seconds
                                                ):
                                                    warned_extended = True
                                                    debug_print(
                                                        "⏳ Still 403 after grace window; waiting for proxy job completion..."
                                                    )
                                                yield SSE_KEEPALIVE
                                                await asyncio.sleep(0.5)

                                    # If the userscript proxy recovered (status changed after in-page retries),
                                    # proceed to normal stream parsing below.
                                    if response.status_code != HTTPStatus.FORBIDDEN:
                                        pass
                                    else:
                                        retry_403_count += 1
                                        if retry_403_count > 5:
                                            yield f"data: {json.dumps(openai_error_payload('Forbidden (403) from upstream. Retries exhausted.', 'forbidden_error', HTTPStatus.FORBIDDEN))}\n\n"
                                            yield SSE_DONE
                                            return

                                        body_text = ""
                                        error_body = None
                                        try:
                                            body_bytes = await response.aread()
                                            body_text = body_bytes.decode("utf-8", errors="replace")
                                            error_body = json.loads(body_text)
                                        except Exception:
                                            error_body = None
                                            # If it's not JSON, we'll use the body_text for keyword matching.

                                        is_recaptcha_failure = False
                                        try:
                                            if (
                                                isinstance(error_body, dict)
                                                and error_body.get("error") == "recaptcha validation failed"
                                            ):
                                                is_recaptcha_failure = True
                                            elif "recaptcha validation failed" in str(body_text).lower():
                                                is_recaptcha_failure = True
                                        except Exception:
                                            is_recaptcha_failure = False

                                        if transport_used == "userscript":
                                            # The proxy is our only truly streaming browser transport. Prefer retrying
                                            # it with a fresh in-page token mint over switching to buffered browser
                                            # fetch fallbacks (which can stall SSE).
                                            force_proxy_recaptcha_mint = True
                                            if is_recaptcha_failure:
                                                recaptcha_403_failures += 1
                                                if recaptcha_403_failures >= 5:
                                                    debug_print(
                                                        "? Too many reCAPTCHA failures in userscript proxy. Failing fast."
                                                    )
                                                    yield f"data: {json.dumps(openai_error_payload('Forbidden: reCAPTCHA validation failed repeatedly in userscript proxy.', 'recaptcha_error', HTTPStatus.FORBIDDEN))}\n\n"
                                                    yield SSE_DONE
                                                    return

                                            if isinstance(payload, dict):
                                                payload["recaptchaV3Token"] = ""
                                                payload.pop("recaptchaV2Token", None)

                                            async for ka in sse_sleep_with_keepalive(core, 1.5):
                                                yield ka
                                            continue

                                        if is_recaptcha_failure:
                                            # Track consecutive reCAPTCHA failures so we can escalate to browser
                                            # transports even for non-strict models.
                                            recaptcha_403_failures += 1
                                            if recaptcha_403_last_transport == transport_used:
                                                recaptcha_403_consecutive += 1
                                            else:
                                                recaptcha_403_consecutive = 1
                                                recaptcha_403_last_transport = transport_used

                                            if transport_used in ("chrome", "camoufox"):
                                                try:
                                                    debug_print(
                                                        "Refreshing token/cookies (side-channel) after browser fetch 403..."
                                                    )
                                                    refresh_task = asyncio.create_task(
                                                        refresh_recaptcha_token(force_new=True)
                                                    )
                                                    async for ka in sse_wait_for_task_with_keepalive(core, refresh_task):
                                                        yield ka
                                                    new_token = refresh_task.result()
                                                except Exception:
                                                    new_token = None
                                                # Prefer reusing a fresh side-channel token on the next attempt; if we
                                                # couldn't get one, fall back to in-page minting.
                                                if isinstance(payload, dict):
                                                    payload["recaptchaV3Token"] = new_token or ""
                                            else:
                                                debug_print("Refreshing token (side-channel)...")
                                                try:
                                                    refresh_task = asyncio.create_task(
                                                        refresh_recaptcha_token(force_new=True)
                                                    )
                                                    async for ka in sse_wait_for_task_with_keepalive(core, refresh_task):
                                                        yield ka
                                                    new_token = refresh_task.result()
                                                except Exception:
                                                    new_token = None
                                                if new_token and isinstance(payload, dict):
                                                    payload["recaptchaV3Token"] = new_token

                                            if recaptcha_403_consecutive >= 2 and transport_used == "chrome":
                                                debug_print(
                                                    "Switching to Camoufox-first after repeated Chrome reCAPTCHA failures."
                                                )
                                                use_browser_transports = True
                                                prefer_chrome_transport = False
                                                recaptcha_403_consecutive = 0
                                                recaptcha_403_last_transport = None
                                            elif recaptcha_403_consecutive >= 2 and transport_used != "chrome":
                                                debug_print(
                                                    "🌐 Switching to Chrome fetch transport after repeated reCAPTCHA failures."
                                                )
                                                use_browser_transports = True
                                                prefer_chrome_transport = True
                                                recaptcha_403_consecutive = 0
                                                recaptcha_403_last_transport = None

                                            async for ka in sse_sleep_with_keepalive(core, 1.5):
                                                yield ka
                                            continue

                                        # If 403 but not recaptcha, might be other auth issue, but let's retry anyway
                                        async for ka in sse_sleep_with_keepalive(core, 2.0):
                                            yield ka
                                        continue

                                elif response.status_code == HTTPStatus.UNAUTHORIZED:
                                    if strict_chrome_fetch_model and use_browser_transports:
                                        # Strict-model requests can recover from 401s by minting a fresh anonymous
                                        # session inside the browser (Camoufox/userscript proxy). Rotating through
                                        # expired config tokens here just produces repeated 401s and forces manual
                                        # token paste. Prefer browser-session retry instead.
                                        debug_print("🔒 Upstream 401 in strict browser mode. Retrying with browser session (no token)...")
                                        current_token = ""
                                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        if isinstance(payload, dict):
                                            payload["recaptchaV3Token"] = ""
                                        async for ka in sse_sleep_with_keepalive(core, 2.0):
                                            yield ka
                                        continue

                                    debug_print(f"🔒 Stream token expired")
                                    # Add current token to failed set
                                    if current_token:
                                        failed_tokens.add(current_token)

                                    # Best-effort: refresh the current base64 session in-memory before rotating.
                                    refreshed_token: Optional[str] = None
                                    if current_token:
                                        try:
                                            cfg_now = get_config()
                                        except Exception:
                                            cfg_now = {}
                                        if not isinstance(cfg_now, dict):
                                            cfg_now = {}
                                        try:
                                            refreshed_token = await refresh_arena_auth_token_via_lmarena_http(
                                                current_token, cfg_now
                                            )
                                        except Exception:
                                            refreshed_token = None
                                        if not refreshed_token:
                                            try:
                                                refreshed_token = await refresh_arena_auth_token_via_supabase(current_token)
                                            except Exception:
                                                refreshed_token = None

                                    if refreshed_token:
                                        core.EPHEMERAL_ARENA_AUTH_TOKEN = refreshed_token
                                        current_token = refreshed_token
                                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        # Ensure the next browser attempt mints a fresh token for the refreshed session.
                                        if isinstance(payload, dict):
                                            payload["recaptchaV3Token"] = ""
                                        debug_print("🔄 Refreshed arena-auth-prod-v1 session after 401. Retrying...")
                                        async for ka in sse_sleep_with_keepalive(core, 1.0):
                                            yield ka
                                        continue
                                    
                                    try:
                                        # Try with next available token (excluding failed ones)
                                        current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        debug_print(f"🔄 Retrying stream with next token: {current_token[:20]}...")
                                        async for ka in sse_sleep_with_keepalive(core, 1.0):
                                            yield ka
                                        continue
                                    except HTTPException:
                                        debug_print("No more tokens available for streaming request.")
                                        yield f"data: {json.dumps(openai_error_payload('Unauthorized: Your LMArena auth token has expired or is invalid. Please get a new auth token from the dashboard.', 'authentication_error', HTTPStatus.UNAUTHORIZED))}\n\n"
                                        yield SSE_DONE
                                        return
                                
                                log_http_status(response.status_code, "Stream Connection")
                                response.raise_for_status()
                                
                                async for maybe_line in aiter_with_keepalive(core, response.aiter_lines().__aiter__()):
                                    if maybe_line is None:
                                        yield SSE_KEEPALIVE
                                        continue

                                    line = str(maybe_line).strip()
                                    
                                    # Use the modularized parser to generate OpenAI-compatible SSE chunks
                                    stream_state = {
                                        "response_text": response_text,
                                        "reasoning_text": reasoning_text,
                                        "citations": citations,
                                    }
                                    chunks = parse_lmarena_line_to_openai_chunks(
                                        line, chunk_id, model_public_name, stream_state
                                    )
                                    # Sync back state for upstream failure detection logic
                                    response_text = stream_state["response_text"]
                                    reasoning_text = stream_state["reasoning_text"]
                                    citations = stream_state.get("citations", citations)
                                    
                                    for chunk in chunks:
                                        yield chunk
                                    
                                    if not chunks and line and not line.startswith("data:"):
                                        # Capture a small preview of unhandled upstream lines for troubleshooting.
                                        if len(unhandled_preview) < 5:
                                            unhandled_preview.append(line)
                            
                            # If we got no usable deltas, treat it as an upstream failure and retry.
                            if (not response_text.strip()) and (not reasoning_text.strip()) and (not citations):
                                upstream_hint: Optional[str] = None
                                proxy_status: Optional[int] = None
                                proxy_headers: Optional[dict] = None
                                if transport_used == "userscript":
                                    try:
                                        proxy_job_id = str(getattr(stream_context, "job_id", "") or "").strip()
                                        proxy_job = _USERSCRIPT_PROXY_JOBS.get(proxy_job_id)
                                        if isinstance(proxy_job, dict):
                                            if proxy_job.get("error"):
                                                upstream_hint = str(proxy_job.get("error") or "")
                                            status = proxy_job.get("status_code")
                                            headers = proxy_job.get("headers")
                                            if isinstance(headers, dict):
                                                proxy_headers = headers
                                            if isinstance(status, int) and int(status) >= 400:
                                                proxy_status = int(status)
                                                upstream_hint = upstream_hint or f"Userscript proxy upstream HTTP {int(status)}"
                                    except Exception:
                                        pass

                                if not upstream_hint and unhandled_preview:
                                    # Common case: upstream returns a JSON error body (not a0:/ad: lines).
                                    try:
                                        obj = json.loads(unhandled_preview[0])
                                        if isinstance(obj, dict):
                                            upstream_hint = str(obj.get("error") or obj.get("message") or "")
                                    except Exception:
                                        pass
                                    
                                    if not upstream_hint:
                                        upstream_hint = unhandled_preview[0][:500]

                                debug_print(f"⚠️ Stream produced no content deltas (transport={transport_used}, attempt {attempt}). Retrying...")
                                if upstream_hint:
                                    debug_print(f"   Upstream hint: {upstream_hint[:200]}")
                                    if "recaptcha" in upstream_hint.lower():
                                        recaptcha_403_failures += 1
                                        if recaptcha_403_failures >= 5:
                                            debug_print("❌ Too many reCAPTCHA failures (detected in body). Failing fast.")
                                            yield f"data: {json.dumps(openai_error_payload(f'Forbidden: reCAPTCHA validation failed. Upstream hint: {upstream_hint[:200]}', 'recaptcha_error', HTTPStatus.FORBIDDEN))}\n\n"
                                            yield SSE_DONE
                                            return
                                elif unhandled_preview:
                                    debug_print(f"   Upstream preview: {unhandled_preview[0][:200]}")
                                
                                no_delta_failures += 1
                                if no_delta_failures >= 10:
                                    debug_print("❌ Too many attempts with no content produced. Failing fast.")
                                    msg = (
                                        "Upstream failure: The request produced no content after multiple retries. "
                                        f"Last hint: {upstream_hint[:200] if upstream_hint else 'None'}"
                                    )
                                    yield f"data: {json.dumps(openai_error_payload(msg, 'upstream_error', HTTPStatus.BAD_GATEWAY))}\n\n"
                                    yield SSE_DONE
                                    return

                                # If the userscript proxy actually returned an upstream HTTP error, don't spin forever
                                # sending keep-alives: treat them as the equivalent upstream status and fall back.
                                if transport_used == "userscript" and proxy_status in (
                                    HTTPStatus.UNAUTHORIZED,
                                    HTTPStatus.FORBIDDEN,
                                ):
                                    # Mirror the regular 401/403 handling, but based on the proxy job status instead
                                    # of `response.status_code` (which can be stale for userscript jobs).
                                    if proxy_status == HTTPStatus.UNAUTHORIZED:
                                        debug_print("🔒 Userscript proxy upstream 401. Rotating auth token...")
                                        failed_tokens.add(current_token)
                                        # (Pruning disabled)

                                        try:
                                            current_token = get_next_auth_token(exclude_tokens=failed_tokens)
                                            headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        except HTTPException:
                                            yield f"data: {json.dumps(openai_error_payload('Unauthorized: Your LMArena auth token has expired or is invalid. Please get a new auth token from the dashboard.', 'authentication_error', HTTPStatus.UNAUTHORIZED))}\n\n"
                                            yield SSE_DONE
                                            return

                                    if proxy_status == HTTPStatus.FORBIDDEN:
                                        recaptcha_403_failures += 1
                                        if recaptcha_403_failures >= 5:
                                            debug_print("❌ Too many reCAPTCHA failures in userscript proxy. Failing fast.")
                                            yield f"data: {json.dumps(openai_error_payload('Forbidden: reCAPTCHA validation failed repeatedly in userscript proxy.', 'recaptcha_error', HTTPStatus.FORBIDDEN))}\n\n"
                                            yield SSE_DONE
                                            return

                                        # Common case: the proxy session gets flagged (reCAPTCHA). Retry with a fresh
                                        # in-page token mint rather than switching to buffered browser fetch fallbacks.
                                        force_proxy_recaptcha_mint = True
                                        debug_print("🚫 Userscript proxy upstream 403: retrying userscript (fresh reCAPTCHA).")
                                        if isinstance(payload, dict):
                                            payload["recaptchaV3Token"] = ""
                                            payload.pop("recaptchaV2Token", None)

                                    yield SSE_KEEPALIVE
                                    continue

                                # If the proxy upstream is rate-limited, respect Retry-After/backoff.
                                if transport_used == "userscript" and proxy_status == HTTPStatus.TOO_MANY_REQUESTS:
                                    retry_after = None
                                    if isinstance(proxy_headers, dict):
                                        retry_after = proxy_headers.get("retry-after") or proxy_headers.get("Retry-After")
                                    retry_after_value = 0.0
                                    if isinstance(retry_after, str):
                                        try:
                                            retry_after_value = float(retry_after.strip())
                                        except Exception:
                                            retry_after_value = 0.0
                                    sleep_seconds = get_rate_limit_sleep_seconds(retry_after, attempt)
                                    debug_print(f"⏱️  Userscript proxy upstream 429. Waiting {sleep_seconds}s...")
                                    
                                    # Rotate token on userscript rate limit too.
                                    old_token = current_token
                                    token_rotated = False
                                    try:
                                        rotation_exclude = set(failed_tokens)
                                        if current_token:
                                            rotation_exclude.add(current_token)
                                        current_token = get_next_auth_token(
                                            exclude_tokens=rotation_exclude, allow_ephemeral_fallback=False
                                        )
                                        headers = get_request_headers_with_token(current_token, recaptcha_token)
                                        token_rotated = True
                                        debug_print(f"🔄 Retrying stream with next token (after proxy 429): {current_token[:20]}...")
                                    except HTTPException:
                                        # Only one token (or all tokens excluded). Keep the current token and retry
                                        # after backoff instead of failing fast.
                                        debug_print(
                                            "⚠️ No alternative token available after userscript proxy rate limit; retrying with same token after backoff."
                                        )

                                    # reCAPTCHA v3 tokens can be single-use and may expire while we back off.
                                    # Clear it so the next proxy attempt mints a fresh token in-page.
                                    if isinstance(payload, dict):
                                        payload["recaptchaV3Token"] = ""

                                    # If we rotated tokens, allow a fast retry when waiting would blow past the remaining
                                    # stream deadline (common when one token is rate-limited but another isn't).
                                    if token_rotated and current_token and current_token != old_token:
                                        remaining_budget = float(stream_total_timeout_seconds) - float(
                                            time.monotonic() - stream_started_at
                                        )
                                        if float(sleep_seconds) > max(0.0, remaining_budget):
                                            sleep_seconds = min(float(sleep_seconds), 1.0)

                                    # If we still can't wait within the remaining deadline, fail now instead of sending
                                    # keep-alives indefinitely.
                                    if (time.monotonic() - stream_started_at + float(sleep_seconds)) > stream_total_timeout_seconds:
                                        yield f"data: {json.dumps(openai_error_payload(f'Upstream rate limit (429) would exceed stream deadline ({int(sleep_seconds)}s backoff).', 'rate_limit_error', HTTPStatus.TOO_MANY_REQUESTS))}\n\n"
                                        yield SSE_DONE
                                        return

                                    async for ka in sse_sleep_with_keepalive(core, sleep_seconds):
                                        yield ka
                                else:
                                    async for ka in sse_sleep_with_keepalive(core, 1.5):
                                        yield ka
                                continue

                            # Update session - Store message history with IDs (including reasoning and citations if present)
                            assistant_message = {
                                "id": model_msg_id, 
                                "role": "assistant", 
                                "content": response_text.strip()
                            }
                            if reasoning_text:
                                assistant_message["reasoning_content"] = reasoning_text.strip()
                            if citations:
                                unique_citations, _ = format_citations(citations)
                                assistant_message["citations"] = unique_citations
                            
                            if not session:
                                chat_sessions[api_key_str][conversation_id] = {
                                    "conversation_id": session_id,
                                    "model": model_public_name,
                                    "messages": [
                                        {"id": user_msg_id, "role": "user", "content": prompt},
                                        assistant_message
                                    ]
                                }
                                debug_print(f"💾 Saved new session for conversation {conversation_id}")
                            else:
                                # Append new messages to history
                                chat_sessions[api_key_str][conversation_id]["messages"].append(
                                    {"id": user_msg_id, "role": "user", "content": prompt}
                                )
                                chat_sessions[api_key_str][conversation_id]["messages"].append(
                                    assistant_message
                                )
                                debug_print(f"💾 Updated existing session for conversation {conversation_id}")
                            
                            yield SSE_DONE
                            debug_print(f"✅ Stream completed - {len(response_text)} chars sent")
                            return  # Success, exit retry loop
                                
                    except httpx.HTTPStatusError as e:
                        # Handle retry-able errors
                        if e.response.status_code == 429:
                            current_retry_attempt += 1
                            if current_retry_attempt > max_retries:
                                error_msg = "LMArena API error 429: Too many requests. Max retries exceeded. Terminating stream."
                                debug_print(f"❌ {error_msg}")
                                yield f"data: {json.dumps(openai_error_payload(error_msg, 'api_error', e.response.status_code))}\n\n"
                                yield SSE_DONE
                                return

                            retry_after_header = e.response.headers.get("Retry-After")
                            sleep_seconds = get_rate_limit_sleep_seconds(
                                retry_after_header, current_retry_attempt
                            )
                            debug_print(
                                f"⏱️ LMArena API returned 429 (Too Many Requests). "
                                f"Retrying in {sleep_seconds} seconds (attempt {current_retry_attempt}/{max_retries})."
                            )
                            async for ka in sse_sleep_with_keepalive(core, sleep_seconds):
                                yield ka
                            continue # Continue to the next iteration of the while True loop
                        elif e.response.status_code == 403:
                            current_retry_attempt += 1
                            if current_retry_attempt > max_retries:
                                error_msg = "LMArena API error 403: Forbidden. Max retries exceeded. Terminating stream."
                                debug_print(f"❌ {error_msg}")
                                yield f"data: {json.dumps(openai_error_payload(error_msg, 'api_error', e.response.status_code))}\n\n"
                                yield SSE_DONE
                                return
                            
                            debug_print(
                                f"🚫 LMArena API returned 403 (Forbidden). "
                                f"Retrying with exponential backoff (attempt {current_retry_attempt}/{max_retries})."
                            )
                            sleep_seconds = get_general_backoff_seconds(current_retry_attempt)
                            async for ka in sse_sleep_with_keepalive(core, sleep_seconds):
                                yield ka
                            continue # Continue to the next iteration of the while True loop
                        elif e.response.status_code == 401:
                            # Existing 401 handling (token rotation) will implicitly use the retry loop.
                            # We need to ensure max_retries applies here too.
                            current_retry_attempt += 1
                            if current_retry_attempt > max_retries:
                                error_msg = "LMArena API error 401: Unauthorized. Max retries exceeded. Terminating stream."
                                debug_print(f"❌ {error_msg}")
                                yield f"data: {json.dumps(openai_error_payload(error_msg, 'api_error', e.response.status_code))}\n\n"
                                yield SSE_DONE
                                return
                            # The original code has `continue` here, which leads to an additional keepalive sleep.
                            # This is fine for 401 to allow token rotation and retry.
                            async for ka in sse_sleep_with_keepalive(core, 2.0):
                                yield ka
                            continue
                        else:
                            # Provide user-friendly error messages for non-retryable errors
                            try:
                                body_text = ""
                                try:
                                    raw = await e.response.aread()
                                    if isinstance(raw, (bytes, bytearray)):
                                        body_text = raw.decode("utf-8", errors="replace")
                                    else:
                                        body_text = str(raw)
                                except Exception:
                                    body_text = ""
                                body_text = str(body_text or "").strip()
                                if body_text:
                                    preview = body_text[:800]
                                    error_msg = f"LMArena API error {e.response.status_code}: {preview}"
                                else:
                                    error_msg = f"LMArena API error: {e.response.status_code}"
                            except Exception:
                                error_msg = f"LMArena API error: {e.response.status_code}"
                            
                            error_type = "api_error"
                            
                            debug_print(f"❌ {error_msg}")
                            yield f"data: {json.dumps(openai_error_payload(error_msg, error_type, e.response.status_code))}\n\n"
                            yield SSE_DONE
                            return
                    except Exception as e:
                        debug_print(f"❌ Stream error: {str(e)}")
                        # If it's a connection error, we might want to retry indefinitely too? 
                        # For now, let's treat generic exceptions as transient if possible, or just fail safely.
                        # Given "until real content deltas arrive", we should probably be aggressive with retries.
                        # But legitimate internal errors should probably surface.
                        # Let's retry on network-like errors if we can distinguish them.
                        # For now, yield error.
                        yield f"data: {json.dumps(openai_error_payload(str(e), 'internal_error', 'internal_error'))}\n\n"
                        yield SSE_DONE
                        return
            return StreamingResponse(generate_stream(), media_type="text/event-stream")
        
        # Handle non-streaming mode with retry
        try:
            if not _userscript_proxy_is_active():
                raise HTTPException(
                    status_code=503,
                    detail="Userscript proxy is required for non-streaming requests. Start the Camoufox proxy worker/userscript bridge and retry.",
                )

            debug_print("🌐 Userscript Proxy is ACTIVE. Delegating non-streaming request...")
            proxy_auth_token = str(current_token or "").strip()
            try:
                if (
                    proxy_auth_token
                    and not str(proxy_auth_token).startswith("base64-")
                    and is_arena_auth_token_expired(proxy_auth_token, skew_seconds=0)
                ):
                    proxy_auth_token = ""
            except Exception:
                pass

            if isinstance(payload, dict):
                payload["recaptchaV3Token"] = ""

            response = await fetch_via_proxy_queue(
                url=url,
                payload=payload if isinstance(payload, dict) else {},
                http_method=http_method,
                timeout_seconds=120,
                auth_token=proxy_auth_token,
            )
            if response is None:
                raise HTTPException(
                    status_code=504,
                    detail="Userscript proxy request timed out or returned no response.",
                )

            response.raise_for_status()
                 
            log_http_status(response.status_code, "LMArena API Response")
             
            # Use aread() to ensure we buffer streaming-capable responses (like BrowserFetchStreamResponse)
            response_bytes = await response.aread()
            response_text_body = response_bytes.decode("utf-8", errors="replace")
            
            debug_print(f"📏 Response length: {len(response_text_body)} characters")
            debug_print(f"📋 Response headers: {dict(response.headers)}")
            
            debug_print(f"🔍 Processing response...")
            debug_print(f"📄 First 500 chars of response:\n{response_text_body[:500]}")
            
            # Process response in lmarena format
            # Format: ag:"thinking" for reasoning, a0:"text chunk" for content, ac:{...} for citations, ad:{...} for metadata
            response_text = ""
            reasoning_text = ""
            citations = []
            finish_reason = None
            line_count = 0
            text_chunks_found = 0
            reasoning_chunks_found = 0
            citation_chunks_found = 0
            metadata_found = 0
            
            debug_print(f"📊 Parsing response lines...")
            
            error_message = None
            for line in response_text_body.splitlines():
                line_count += 1
                line = line.strip()
                if line.startswith("data: "):
                    line = line[6:].strip()
                if not line:
                    continue
                
                # Parse thinking/reasoning chunks: ag:"thinking text"
                if line.startswith("ag:"):
                    chunk_data = line[3:]  # Remove "ag:" prefix
                    reasoning_chunks_found += 1
                    try:
                        # Parse as JSON string (includes quotes)
                        reasoning_chunk = json.loads(chunk_data)
                        reasoning_text += reasoning_chunk
                        if reasoning_chunks_found <= 3:  # Log first 3 reasoning chunks
                            debug_print(f"  🧠 Reasoning chunk {reasoning_chunks_found}: {repr(reasoning_chunk[:50])}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse reasoning chunk on line {line_count}: {chunk_data[:100]} - {e}")
                        continue
                
                # Parse text chunks: a0:"Hello "
                elif line.startswith("a0:"):
                    chunk_data = line[3:]  # Remove "a0:" prefix
                    text_chunks_found += 1
                    try:
                        # Parse as JSON string (includes quotes)
                        text_chunk = json.loads(chunk_data)
                        response_text += text_chunk
                        if text_chunks_found <= 3:  # Log first 3 chunks
                            debug_print(f"  ✅ Chunk {text_chunks_found}: {repr(text_chunk[:50])}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse text chunk on line {line_count}: {chunk_data[:100]} - {e}")
                        continue
                
                # Parse image generation: a2:[{...}] (for image models)
                elif line.startswith("a2:"):
                    image_data = line[3:]  # Remove "a2:" prefix
                    try:
                        image_list = json.loads(image_data)
                        # OpenAI format expects URL in content
                        if isinstance(image_list, list) and len(image_list) > 0:
                            image_obj = image_list[0]
                            if image_obj.get('type') == 'image':
                                image_url = image_obj.get('image', '')
                                # Format as markdown
                                response_text = f"![Generated Image]({image_url})"
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse image data on line {line_count}: {image_data[:100]} - {e}")
                        continue
                
                # Parse citations/tool calls: ac:{...} (for search models)
                elif line.startswith("ac:"):
                    citation_data = line[3:]  # Remove "ac:" prefix
                    citation_chunks_found += 1
                    try:
                        citation_obj = json.loads(citation_data)
                        # Extract source information from argsTextDelta
                        if 'argsTextDelta' in citation_obj:
                            args_data = json.loads(citation_obj['argsTextDelta'])
                            if 'source' in args_data:
                                source = args_data['source']
                                # Can be a single source or array of sources
                                if isinstance(source, list):
                                    citations.extend(source)
                                elif isinstance(source, dict):
                                    citations.append(source)
                        if citation_chunks_found <= 3:  # Log first 3 citations
                            debug_print(f"  🔗 Citation chunk {citation_chunks_found}: {citation_obj.get('toolCallId')}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse citation chunk on line {line_count}: {citation_data[:100]} - {e}")
                        continue
                
                # Parse error messages: a3:"An error occurred"
                elif line.startswith("a3:"):
                    error_data = line[3:]  # Remove "a3:" prefix
                    try:
                        error_message = json.loads(error_data)
                        debug_print(f"  ❌ Error message received: {error_message}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse error message on line {line_count}: {error_data[:100]} - {e}")
                        error_message = error_data
                
                # Parse metadata: ad:{"finishReason":"stop"}
                elif line.startswith("ad:"):
                    metadata_data = line[3:]  # Remove "ad:" prefix
                    metadata_found += 1
                    try:
                        metadata = json.loads(metadata_data)
                        finish_reason = metadata.get("finishReason")
                        debug_print(f"  📋 Metadata found: finishReason={finish_reason}")
                    except json.JSONDecodeError as e:
                        debug_print(f"  ⚠️ Failed to parse metadata on line {line_count}: {metadata_data[:100]} - {e}")
                        continue
                elif line.strip():  # Non-empty line that doesn't match expected format
                    if line_count <= 5:  # Log first 5 unexpected lines
                        debug_print(f"  ❓ Unexpected line format {line_count}: {line[:100]}")

            debug_print(f"\n📊 Parsing Summary:")
            debug_print(f"  - Total lines: {line_count}")
            debug_print(f"  - Reasoning chunks found: {reasoning_chunks_found}")
            debug_print(f"  - Text chunks found: {text_chunks_found}")
            debug_print(f"  - Citation chunks found: {citation_chunks_found}")
            debug_print(f"  - Metadata entries: {metadata_found}")
            debug_print(f"  - Final response length: {len(response_text)} chars")
            debug_print(f"  - Final reasoning length: {len(reasoning_text)} chars")
            debug_print(f"  - Citations found: {len(citations)}")
            debug_print(f"  - Finish reason: {finish_reason}")
            
            if not response_text:
                debug_print(f"\n⚠️  WARNING: Empty response text!")
                debug_print(f"📄 Full raw response:\n{response_text_body}")
                if error_message:
                    error_detail = f"LMArena API error: {error_message}"
                    print(f"❌ {error_detail}")
                    return openai_error_payload(error_detail, "upstream_error", "lmarena_error")
                else:
                    error_detail = "LMArena API returned empty response. This could be due to: invalid auth token, expired cf_clearance, model unavailable, or API rate limiting."
                    debug_print(f"❌ {error_detail}")
                    return openai_error_payload(error_detail, "upstream_error", "empty_response")
            else:
                debug_print(f"✅ Response text preview: {response_text[:200]}...")
            
            # Update session - Store message history with IDs (including reasoning and citations if present)
            assistant_message = {
                "id": model_msg_id, 
                "role": "assistant", 
                "content": response_text.strip()
            }
            if reasoning_text:
                assistant_message["reasoning_content"] = reasoning_text.strip()
            unique_citations = []
            citation_footnotes = ""
            if citations:
                unique_citations, citation_footnotes = format_citations(citations)
                assistant_message["citations"] = unique_citations

            if not session:
                chat_sessions[api_key_str][conversation_id] = {
                    "conversation_id": session_id,
                    "model": model_public_name,
                    "messages": [
                        {"id": user_msg_id, "role": "user", "content": prompt},
                        assistant_message
                    ]
                }
                debug_print(f"💾 Saved new session for conversation {conversation_id}")
            else:
                # Append new messages to history
                chat_sessions[api_key_str][conversation_id]["messages"].append(
                    {"id": user_msg_id, "role": "user", "content": prompt}
                )
                chat_sessions[api_key_str][conversation_id]["messages"].append(
                    assistant_message
                )
                debug_print(f"💾 Updated existing session for conversation {conversation_id}")

            # Build message object with reasoning and citations if present
            message_obj = {
                "role": "assistant",
                "content": response_text.strip(),
            }
            if reasoning_text:
                message_obj["reasoning_content"] = reasoning_text.strip()
            if citations:
                message_obj["citations"] = unique_citations
                if citation_footnotes:
                    message_obj["content"] = response_text.strip() + citation_footnotes

            # Image models already have markdown formatting from parsing
            # No additional conversion needed
            
            # Calculate token counts (including reasoning tokens)
            prompt_tokens = len(prompt)
            completion_tokens = len(response_text)
            reasoning_tokens = len(reasoning_text)
            total_tokens = prompt_tokens + completion_tokens + reasoning_tokens
            
            # Build usage object with reasoning tokens if present
            usage_obj = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            }
            if reasoning_tokens > 0:
                usage_obj["reasoning_tokens"] = reasoning_tokens
            
            final_response = {
                "id": f"chatcmpl-{uuid.uuid4()}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model_public_name,
                "conversation_id": conversation_id,
                "choices": [{
                    "index": 0,
                    "message": message_obj,
                    "finish_reason": "stop"
                }],
                "usage": usage_obj
            }
            
            debug_print(f"\n✅ REQUEST COMPLETED SUCCESSFULLY")
            debug_print("="*80 + "\n")
            
            return final_response

        except httpx.HTTPStatusError as e:
            # Log error status
            log_http_status(e.response.status_code, "Error Response")
            
            # Try to parse JSON error response from LMArena
            lmarena_error = None
            try:
                error_body = e.response.json()
                if isinstance(error_body, dict) and "error" in error_body:
                    lmarena_error = error_body["error"]
                    debug_print(f"📛 LMArena error message: {lmarena_error}")
            except:
                pass
            
            # Provide user-friendly error messages
            if e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                error_detail = "Rate limit exceeded on LMArena. Please try again in a few moments."
                error_type = "rate_limit_error"
            elif e.response.status_code == HTTPStatus.UNAUTHORIZED:
                error_detail = "Unauthorized: Your LMArena auth token has expired or is invalid. Please get a new auth token from the dashboard."
                error_type = "authentication_error"
            elif e.response.status_code == HTTPStatus.FORBIDDEN:
                error_detail = f"Forbidden: Access to this resource is denied. {e.response.text}"
                error_type = "forbidden_error"
            elif e.response.status_code == HTTPStatus.NOT_FOUND:
                error_detail = "Not Found: The requested resource doesn't exist."
                error_type = "not_found_error"
            elif e.response.status_code == HTTPStatus.BAD_REQUEST:
                # Use LMArena's error message if available
                if lmarena_error:
                    error_detail = f"Bad Request: {lmarena_error}"
                else:
                    error_detail = f"Bad Request: Invalid request parameters. {e.response.text}"
                error_type = "bad_request_error"
            elif e.response.status_code >= 500:
                error_detail = f"Server Error: LMArena API returned {e.response.status_code}"
                error_type = "server_error"
            else:
                error_detail = f"LMArena API error {e.response.status_code}: {e.response.text}"
                error_type = "upstream_error"
            
            print(f"\n❌ HTTP STATUS ERROR")
            print(f"📛 Error detail: {error_detail}")
            print(f"📤 Request URL: {url}")
            debug_print(f"📤 Request payload (truncated): {json.dumps(payload, indent=2)[:500]}")
            debug_print(f"📥 Response text: {e.response.text[:500]}")
            print("="*80 + "\n")
            
            return openai_error_payload(error_detail, error_type, f"http_{e.response.status_code}")
        
        except httpx.TimeoutException as e:
            print(f"\n⏱️  TIMEOUT ERROR")
            print(f"📛 Request timed out after 120 seconds")
            print(f"📤 Request URL: {url}")
            print("="*80 + "\n")
            return openai_error_payload("Request to LMArena API timed out after 120 seconds", "timeout_error", "request_timeout")
        
        except Exception as e:
            print(f"\n❌ UNEXPECTED ERROR IN HTTP CLIENT")
            print(f"📛 Error type: {type(e).__name__}")
            print(f"📛 Error message: {str(e)}")
            print(f"📤 Request URL: {url}")
            print("="*80 + "\n")
            return openai_error_payload(f"Unexpected error: {str(e)}", "internal_error", type(e).__name__.lower())
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ TOP-LEVEL EXCEPTION")
        print(f"📛 Error type: {type(e).__name__}")
        print(f"📛 Error message: {str(e)}")
        print("="*80 + "\n")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

