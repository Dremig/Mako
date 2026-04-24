from __future__ import annotations

import json
import math
import os
import random
import re
import ssl
import time
import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

_EMBED_MODEL_CACHE: dict[str, str] = {}


def load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def _read_access_token_from_auth_json(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    tokens = payload.get("tokens")
    if not isinstance(tokens, dict):
        return ""
    token = str(tokens.get("access_token", "")).strip()
    return token


def require_openai_auth_token(root: Path | None = None) -> str:
    token = os.getenv("OPENAI_ACCESS_TOKEN", "").strip()
    if token:
        return token

    auth_json_candidates: list[Path] = []
    auth_json_env = os.getenv("OPENAI_AUTH_JSON", "").strip()
    if auth_json_env:
        auth_json_candidates.append(Path(auth_json_env).expanduser())
    if root is not None:
        auth_json_candidates.append((root / "auth.json").resolve())
    auth_json_candidates.append(Path("auth.json").resolve())

    seen: set[Path] = set()
    for candidate in auth_json_candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if not candidate.exists() or not candidate.is_file():
            continue
        token = _read_access_token_from_auth_json(candidate)
        if token:
            return token

    if os.getenv("OPENAI_API_KEY", "").strip():
        raise RuntimeError(
            "OPENAI_API_KEY is disabled by policy. "
            "Use OPENAI_ACCESS_TOKEN or provide auth.json with tokens.access_token."
        )
    raise RuntimeError(
        "Missing auth token. Set OPENAI_ACCESS_TOKEN or provide auth.json with tokens.access_token."
    )


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _tls_mode() -> str:
    if _env_truthy("OPENAI_INSECURE_TLS"):
        return "insecure"
    mode = os.getenv("OPENAI_TLS_MODE", "auto").strip().lower()
    return mode if mode in {"auto", "strict", "insecure"} else "auto"


def _is_official_openai_host(base_url: str) -> bool:
    host = (urllib.parse.urlparse(base_url).hostname or "").lower()
    return host in {"api.openai.com", "openai.com"}


def _should_bypass_proxy(base_url: str) -> bool:
    if _env_truthy("OPENAI_BYPASS_PROXY"):
        return True
    host = (urllib.parse.urlparse(base_url).hostname or "").strip().lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def _api_mode(base_url: str) -> str:
    raw = os.getenv("OPENAI_API_MODE", "auto").strip().lower()
    if raw in {"chat", "responses"}:
        return raw
    return "responses" if _is_official_openai_host(base_url) else "chat"


def _responses_reasoning() -> dict[str, Any] | None:
    effort = os.getenv("OPENAI_REASONING_EFFORT", "").strip().lower()
    if effort not in {"minimal", "low", "medium", "high"}:
        return None
    return {"effort": effort}


def _responses_force_stream() -> bool:
    return _env_truthy("OPENAI_RESPONSES_FORCE_STREAM")


def _responses_disable_previous_response_id() -> bool:
    return _env_truthy("OPENAI_RESPONSES_DISABLE_PREVIOUS_RESPONSE_ID")


def _responses_use_local_msgchain() -> bool:
    return _env_truthy("OPENAI_LOCAL_MSGCHAIN")


def _responses_replay_max_messages() -> int:
    raw = os.getenv("OPENAI_REPLAY_MAX_MESSAGES", "80").strip()
    try:
        value = int(raw)
    except ValueError:
        return 80
    return max(8, min(value, 400))


def _responses_long_memory_enabled() -> bool:
    raw = os.getenv("OPENAI_LONG_TERM_MEMORY", "true").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _responses_long_memory_max_items() -> int:
    raw = os.getenv("OPENAI_LONG_TERM_MAX_ITEMS", "64").strip()
    try:
        value = int(raw)
    except ValueError:
        return 64
    return max(8, min(value, 256))


def _responses_long_memory_recall_topk() -> int:
    raw = os.getenv("OPENAI_LONG_TERM_RECALL_TOPK", "3").strip()
    try:
        value = int(raw)
    except ValueError:
        return 3
    return max(1, min(value, 12))


def _memory_tokenize(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9_./:-]+", text.lower()) if len(t) >= 3]


def _memory_keywords(text: str, limit: int = 16) -> list[str]:
    stop = {
        "the", "and", "that", "with", "this", "from", "have", "were", "what", "when", "where", "your",
        "http", "https", "json", "role", "content", "user", "assistant", "system", "reply", "only",
    }
    seen: set[str] = set()
    out: list[str] = []
    for tok in _memory_tokenize(text):
        if tok in stop or tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= limit:
            break
    return out


def _normalize_long_term_memory(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        summary = str(item.get("summary", "")).strip()
        keywords = item.get("keywords", [])
        if not summary:
            continue
        if not isinstance(keywords, list):
            keywords = []
        kws = [str(k).strip().lower() for k in keywords if str(k).strip()]
        out.append({"summary": summary, "keywords": kws})
    return out


def _summarize_for_long_term(messages: list[dict[str, str]]) -> str:
    lines: list[str] = []
    for item in messages[-8:]:
        role = str(item.get("role", "")).strip() or "msg"
        content = str(item.get("content", "")).strip().replace("\n", " ")
        if not content:
            continue
        lines.append(f"{role}: {content[:160]}")
    return " | ".join(lines)[:1000]


def _append_long_term_memory(context: dict[str, Any], messages: list[dict[str, str]]) -> None:
    if not messages or not _responses_long_memory_enabled():
        return
    summary = _summarize_for_long_term(messages)
    if not summary:
        return
    memory = _normalize_long_term_memory(context.get("long_term_memory", []))
    entry = {
        "summary": summary,
        "keywords": _memory_keywords(summary),
    }
    memory.append(entry)
    context["long_term_memory"] = memory[-_responses_long_memory_max_items():]


def _recall_long_term_message(context: dict[str, Any], messages: list[dict[str, str]]) -> dict[str, str] | None:
    if not _responses_long_memory_enabled():
        return None
    memory = _normalize_long_term_memory(context.get("long_term_memory", []))
    if not memory:
        return None
    query = " ".join(str(item.get("content", "")) for item in messages[-3:])
    qset = set(_memory_keywords(query, limit=24))
    if not qset:
        return None
    scored: list[tuple[int, dict[str, Any]]] = []
    for item in memory:
        kws = {str(k).strip().lower() for k in item.get("keywords", []) if str(k).strip()}
        score = len(qset & kws)
        if score > 0:
            scored.append((score, item))
    if not scored:
        return None
    scored.sort(key=lambda x: x[0], reverse=True)
    topk = scored[:_responses_long_memory_recall_topk()]
    lines = [f"- {item['summary']}" for _, item in topk]
    return {
        "role": "system",
        "content": "Long-term memory recall:\n" + "\n".join(lines),
    }


def _ssl_context_for(base_url: str, allow_insecure_fallback: bool = False) -> ssl.SSLContext | None:
    mode = _tls_mode()
    if mode == "insecure":
        return ssl._create_unverified_context()
    if allow_insecure_fallback and mode == "auto" and not _is_official_openai_host(base_url):
        print(f"[warn] TLS certificate verification failed for {base_url}; retrying with insecure TLS")
        return ssl._create_unverified_context()
    return None


def _retry_count() -> int:
    raw = os.getenv("OPENAI_HTTP_RETRIES", "3").strip()
    try:
        value = int(raw)
    except ValueError:
        return 3
    return max(1, min(value, 8))


def _retry_delay_sec(attempt: int) -> float:
    raw_cap = os.getenv("OPENAI_HTTP_RETRY_MAX_DELAY_SEC", "6").strip()
    try:
        cap = float(raw_cap)
    except ValueError:
        cap = 6.0
    cap = max(0.2, min(cap, 30.0))
    base = 0.8
    delay = min(cap, base * (2 ** max(0, attempt - 1)))
    jitter = random.uniform(0.0, min(0.35, delay * 0.2))
    return delay + jitter


def _is_retryable_http(code: int) -> bool:
    return code in {408, 409, 425, 429, 500, 502, 503, 504}


def _http_timeout_sec(default: int) -> int:
    raw = os.getenv("OPENAI_HTTP_TIMEOUT_SEC", "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    return max(5, min(val, 300))


def _http_retry_budget_sec() -> float:
    raw = os.getenv("OPENAI_HTTP_RETRY_BUDGET_SEC", "45").strip()
    try:
        val = float(raw)
    except ValueError:
        val = 45.0
    return max(5.0, min(val, 300.0))


def _build_opener(base_url: str, context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = []
    if _should_bypass_proxy(base_url):
        handlers.append(urllib.request.ProxyHandler({}))
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def post_json(base_url: str, path: str, api_key: str, payload: dict[str, Any], timeout: int = 120) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    timeout = _http_timeout_sec(timeout)
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    retries = _retry_count()
    deadline = time.monotonic() + _http_retry_budget_sec()
    for attempt in range(1, retries + 1):
        if time.monotonic() >= deadline:
            break
        try:
            context = _ssl_context_for(base_url)
            opener = _build_opener(base_url, context)
            with opener.open(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            if _is_retryable_http(int(exc.code)) and attempt < retries:
                sleep_sec = min(_retry_delay_sec(attempt), max(0.0, deadline - time.monotonic()))
                if sleep_sec > 0:
                    time.sleep(sleep_sec)
                continue
            raise RuntimeError(f"HTTP {exc.code} from {url}: {detail[:1000]}") from exc
        except urllib.error.URLError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc) and _tls_mode() == "auto":
                try:
                    context = _ssl_context_for(base_url, allow_insecure_fallback=True)
                    opener = _build_opener(base_url, context)
                    with opener.open(req, timeout=timeout) as resp:
                        return json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as retry_exc:
                    detail = retry_exc.read().decode("utf-8", errors="ignore")
                    if _is_retryable_http(int(retry_exc.code)) and attempt < retries:
                        sleep_sec = min(_retry_delay_sec(attempt), max(0.0, deadline - time.monotonic()))
                        if sleep_sec > 0:
                            time.sleep(sleep_sec)
                        continue
                    raise RuntimeError(f"HTTP {retry_exc.code} from {url}: {detail[:1000]}") from retry_exc
                except Exception as retry_exc:
                    if attempt < retries:
                        sleep_sec = min(_retry_delay_sec(attempt), max(0.0, deadline - time.monotonic()))
                        if sleep_sec > 0:
                            time.sleep(sleep_sec)
                        continue
                    raise RuntimeError(f"Network error for {url}: {retry_exc}") from retry_exc
            if attempt < retries:
                sleep_sec = min(_retry_delay_sec(attempt), max(0.0, deadline - time.monotonic()))
                if sleep_sec > 0:
                    time.sleep(sleep_sec)
                continue
            raise RuntimeError(f"Network error for {url}: {exc}") from exc
        except Exception as exc:
            if attempt < retries:
                sleep_sec = min(_retry_delay_sec(attempt), max(0.0, deadline - time.monotonic()))
                if sleep_sec > 0:
                    time.sleep(sleep_sec)
                continue
            raise RuntimeError(f"Network error for {url}: {exc}") from exc
    raise RuntimeError(f"Network error for {url}: retry budget exhausted")


def _messages_to_responses_input(messages: list[dict[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in messages:
        role = str(item.get("role", "user")).strip() or "user"
        content = str(item.get("content", ""))
        content_type = "output_text" if role == "assistant" else "input_text"
        out.append(
            {
                "role": role,
                "content": [
                    {
                        "type": content_type,
                        "text": content,
                    }
                ],
            }
        )
    return out


def _response_output_text(data: dict[str, Any]) -> str:
    direct = data.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct

    texts: list[str] = []
    for item in data.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue
            ctype = str(content.get("type", "")).strip().lower()
            if ctype not in {"output_text", "text"}:
                continue
            text_val = content.get("text")
            if isinstance(text_val, str) and text_val:
                texts.append(text_val)
                continue
            if isinstance(text_val, dict):
                value = text_val.get("value")
                if isinstance(value, str) and value:
                    texts.append(value)
    return "\n".join(part for part in texts if part).strip()


def _extract_response_id_from_payload(payload: dict[str, Any], event_type: str = "") -> str:
    response_obj = payload.get("response")
    if isinstance(response_obj, dict):
        rid = response_obj.get("id")
        if isinstance(rid, str) and rid.strip():
            return rid.strip()
    direct = payload.get("response_id")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    if event_type in {"response.created", "response.in_progress", "response.completed"}:
        rid = payload.get("id")
        if isinstance(rid, str) and rid.strip():
            return rid.strip()
    rid = payload.get("id")
    if isinstance(rid, str) and rid.strip() and not event_type:
        return rid.strip()
    return ""


def _stream_response_events(raw: str) -> tuple[str, str]:
    parts: list[str] = []
    response_id = ""
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            item = json.loads(payload)
        except Exception:
            continue
        event_type = str(item.get("type", "")).strip()
        if not response_id and isinstance(item, dict):
            response_id = _extract_response_id_from_payload(item, event_type=event_type)
        if event_type == "response.output_text.delta":
            delta = item.get("delta")
            if isinstance(delta, str) and delta:
                parts.append(delta)
            continue
        if event_type == "response.output_text.done":
            text = item.get("text")
            if isinstance(text, str) and text and not parts:
                parts.append(text)
    return "".join(parts).strip(), response_id


def _normalize_replay_messages(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "")).strip()
        content = str(item.get("content", ""))
        if role and content:
            out.append({"role": role, "content": content})
    return out


def _merge_replay_messages(
    *,
    context: dict[str, Any],
    messages: list[dict[str, str]],
) -> list[dict[str, str]]:
    recalled = _recall_long_term_message(context, messages)
    replay = _normalize_replay_messages(context.get("replay_messages", []))
    merged: list[dict[str, str]] = []
    if recalled is not None:
        merged.append(recalled)
    if replay:
        merged.extend(replay)
    merged.extend(messages)
    return merged


def _update_replay_messages(
    *,
    context: dict[str, Any],
    messages: list[dict[str, str]],
    assistant_text: str,
) -> None:
    replay = _normalize_replay_messages(context.get("replay_messages", []))
    replay.extend({"role": str(item.get("role", "")).strip(), "content": str(item.get("content", ""))} for item in messages)
    if assistant_text.strip():
        replay.append({"role": "assistant", "content": assistant_text})
    # Keep a bounded replay window so gateway fallback cannot grow without limit.
    max_keep = _responses_replay_max_messages()
    if len(replay) > max_keep:
        _append_long_term_memory(context, replay[:-max_keep])
    context["replay_messages"] = replay[-max_keep:]


def responses_create(
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: int = 120,
) -> dict[str, Any]:
    return post_json(base_url, "/responses", api_key, payload, timeout=timeout)


def _responses_text_stream(
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: int = 120,
) -> tuple[str, str]:
    request_payload = dict(payload)
    request_payload["stream"] = True
    url = base_url.rstrip("/") + "/responses"
    timeout = _http_timeout_sec(timeout)
    req = urllib.request.Request(
        url=url,
        data=json.dumps(request_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    context = _ssl_context_for(base_url)
    opener = _build_opener(base_url, context)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail[:1000]}") from exc
    except Exception as exc:
        raise RuntimeError(f"Network error for {url}: {exc}") from exc
    text, response_id = _stream_response_events(raw)
    if text:
        return text, response_id
    raise RuntimeError("Streaming Responses API returned no text output")


def responses_text_with_meta(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    text_format: dict[str, Any] | None = None,
    response_context: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    def _call_once(request_payload: dict[str, Any]) -> tuple[str, str]:
        if _responses_force_stream():
            return _responses_text_stream(base_url, api_key, request_payload)
        try:
            data = responses_create(base_url, api_key, request_payload)
            text = _response_output_text(data)
            if text:
                rid = _extract_response_id_from_payload(data)
                return text, rid
            raise RuntimeError("Responses API returned no text output")
        except RuntimeError as exc:
            if "Stream must be set to true" not in str(exc):
                raise
            return _responses_text_stream(base_url, api_key, request_payload)

    context_out = response_context if isinstance(response_context, dict) else {}
    disable_prev = _responses_disable_previous_response_id()
    use_local_msgchain = _responses_use_local_msgchain()
    request_messages = messages
    if isinstance(response_context, dict):
        disable_prev = bool(response_context.get("disable_previous_response_id", False)) or disable_prev
        use_local_msgchain = bool(response_context.get("use_local_msgchain", False)) or use_local_msgchain
        if use_local_msgchain:
            disable_prev = True
        if disable_prev or use_local_msgchain:
            request_messages = _merge_replay_messages(context=response_context, messages=messages)
    if isinstance(context_out, dict):
        context_out["use_local_msgchain"] = bool(use_local_msgchain)

    payload: dict[str, Any] = {
        "model": model,
        "input": _messages_to_responses_input(request_messages),
        "temperature": temperature,
    }
    previous_response_id = ""
    if isinstance(response_context, dict):
        previous_response_id = str(response_context.get("previous_response_id", "")).strip()
        if previous_response_id and not disable_prev and not _responses_disable_previous_response_id():
            payload["previous_response_id"] = previous_response_id
    reasoning = _responses_reasoning()
    if reasoning is not None:
        payload["reasoning"] = reasoning
    if text_format is not None:
        payload["text"] = {"format": text_format}

    used_prev = "previous_response_id" in payload
    try:
        text, response_id = _call_once(payload)
        if response_id:
            context_out["previous_response_id"] = response_id
        if disable_prev or use_local_msgchain:
            _update_replay_messages(context=context_out, messages=messages, assistant_text=text)
        return text, context_out
    except RuntimeError:
        if not used_prev:
            raise
        # Some OpenAI-compatible gateways reject previous_response_id while supporting
        # /responses. Retry once without chained response id and disable it for this context.
        payload.pop("previous_response_id", None)
        payload["input"] = _messages_to_responses_input(_merge_replay_messages(context=context_out, messages=messages))
        text, response_id = _call_once(payload)
        context_out["disable_previous_response_id"] = True
        if response_id:
            context_out["previous_response_id"] = response_id
        _update_replay_messages(context=context_out, messages=messages, assistant_text=text)
        return text, context_out


def responses_text(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    text_format: dict[str, Any] | None = None,
    response_context: dict[str, Any] | None = None,
) -> str:
    text, _ = responses_text_with_meta(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        temperature=temperature,
        text_format=text_format,
        response_context=response_context,
    )
    return text


def _stream_chunks_to_text(raw: str) -> str:
    parts: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            item = json.loads(payload)
        except Exception:
            continue
        choices = item.get("choices", [])
        if not isinstance(choices, list):
            continue
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta", {})
            if not isinstance(delta, dict):
                continue
            content = delta.get("content")
            if isinstance(content, str) and content:
                parts.append(content)
    return "".join(parts).strip()


def _chat_completion_stream(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float,
) -> str:
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": True,
    }
    url = base_url.rstrip("/") + "/chat/completions"
    timeout = _http_timeout_sec(120)
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    context = _ssl_context_for(base_url)
    opener = _build_opener(base_url, context)
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
    text = _stream_chunks_to_text(raw)
    if text:
        return text
    raise RuntimeError("Streaming chat completion returned no text output")


def _is_unsupported_embedding_error(message: str) -> bool:
    text = message.lower()
    return "operationnotsupported" in text or "does not work with the specified model" in text


def _embedding_fallback_models(requested_model: str) -> list[str]:
    ordered = [requested_model, "text-embedding-3-small", "text-embedding-3-large", "text-embedding-ada-002"]
    seen: set[str] = set()
    out: list[str] = []
    for model in ordered:
        model = model.strip()
        if model and model not in seen:
            seen.add(model)
            out.append(model)
    return out


def embed_texts(base_url: str, api_key: str, model: str, texts: list[str]) -> list[list[float]]:
    cache_key = f"{base_url.rstrip('/')}::{model}"
    candidates = _embedding_fallback_models(_EMBED_MODEL_CACHE.get(cache_key, model))
    last_error: RuntimeError | None = None

    for candidate in candidates:
        payload = {
            "model": candidate,
            "input": texts,
        }
        try:
            data = post_json(base_url, "/embeddings", api_key, payload)
            _EMBED_MODEL_CACHE[cache_key] = candidate
            if candidate != model:
                print(f"[embed] fallback model selected: {candidate}")
            return [item["embedding"] for item in data["data"]]
        except RuntimeError as exc:
            last_error = exc
            if candidate == candidates[-1] or not _is_unsupported_embedding_error(str(exc)):
                raise
            continue

    if last_error is not None:
        raise last_error
    raise RuntimeError("Embedding request failed without a specific error")


def chat_completion(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    response_context: dict[str, Any] | None = None,
) -> str:
    if _api_mode(base_url) == "responses":
        text, _ = responses_text_with_meta(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
            response_context=response_context,
        )
        return text
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    try:
        data = post_json(base_url, "/chat/completions", api_key, payload)
        return data["choices"][0]["message"]["content"]
    except RuntimeError as exc:
        if "Stream must be set to true" not in str(exc):
            raise
        return _chat_completion_stream(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
        )


def json_completion(
    base_url: str,
    api_key: str,
    model: str,
    *,
    system_prompt: str,
    user_prompt: str,
    json_schema_name: str,
    json_schema: dict[str, Any],
    temperature: float = 0.1,
    response_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if _api_mode(base_url) == "responses":
        text = responses_text(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            text_format={
                "type": "json_schema",
                "name": json_schema_name,
                "schema": json_schema,
                "strict": True,
            },
            response_context=response_context,
        )
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise RuntimeError(f"Responses JSON output for {json_schema_name} was not an object")
        return parsed

    from web_agent.solver_shared import extract_json

    strict_rules = (
        "CRITICAL OUTPUT RULES:\n"
        "Return exactly one valid JSON object only.\n"
        "Do not output markdown, code fences, comments, or any text before/after JSON.\n"
        "Use double quotes for all keys/strings.\n"
        "If uncertain, keep schema fields with safe defaults instead of adding prose.\n"
    )
    local_user_prompt = user_prompt
    strict_system = system_prompt + "\n" + strict_rules
    for attempt in range(1, 4):
        raw = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=[{"role": "system", "content": strict_system}, {"role": "user", "content": local_user_prompt}],
            temperature=temperature,
            response_context=response_context,
        )
        try:
            parsed = extract_json(raw)
        except Exception:
            if attempt >= 3:
                raise
            local_user_prompt = user_prompt + "\n\nYour previous output was not valid JSON. " + strict_rules
            continue
        if not isinstance(parsed, dict):
            raise RuntimeError(f"JSON output for {json_schema_name} was not an object")
        return parsed
    raise RuntimeError(f"JSON completion failed for {json_schema_name}")


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return -1.0
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for i in range(len(a)):
        ai = a[i]
        bi = b[i]
        dot += ai * bi
        norm_a += ai * ai
        norm_b += bi * bi
    if norm_a <= 0.0 or norm_b <= 0.0:
        return -1.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))
