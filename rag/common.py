from __future__ import annotations

import json
import math
import os
import random
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
        out.append(
            {
                "role": role,
                "content": [
                    {
                        "type": "input_text",
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


def _stream_response_events_to_text(raw: str) -> str:
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
        event_type = str(item.get("type", "")).strip()
        if event_type == "response.output_text.delta":
            delta = item.get("delta")
            if isinstance(delta, str) and delta:
                parts.append(delta)
            continue
        if event_type == "response.output_text.done":
            text = item.get("text")
            if isinstance(text, str) and text and not parts:
                parts.append(text)
    return "".join(parts).strip()


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
) -> str:
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
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
    text = _stream_response_events_to_text(raw)
    if text:
        return text
    raise RuntimeError("Streaming Responses API returned no text output")


def responses_text(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    text_format: dict[str, Any] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "model": model,
        "input": _messages_to_responses_input(messages),
        "temperature": temperature,
    }
    reasoning = _responses_reasoning()
    if reasoning is not None:
        payload["reasoning"] = reasoning
    if text_format is not None:
        payload["text"] = {"format": text_format}
    if _responses_force_stream():
        return _responses_text_stream(base_url, api_key, payload)
    try:
        data = responses_create(base_url, api_key, payload)
        text = _response_output_text(data)
        if text:
            return text
        raise RuntimeError("Responses API returned no text output")
    except RuntimeError as exc:
        if "Stream must be set to true" not in str(exc):
            raise
        return _responses_text_stream(base_url, api_key, payload)


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
) -> str:
    if _api_mode(base_url) == "responses":
        return responses_text(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
        )
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
