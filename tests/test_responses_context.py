from __future__ import annotations

import unittest
from unittest.mock import patch

from rag import common


class ResponsesContextTests(unittest.TestCase):
    def test_stream_event_parser_extracts_text_and_response_id(self) -> None:
        raw = "\n".join(
            [
                'data: {"type":"response.created","response":{"id":"resp_test_1"}}',
                'data: {"type":"response.output_text.delta","delta":"hello"}',
                'data: {"type":"response.output_text.delta","delta":" world"}',
                'data: {"type":"response.output_text.done","text":"hello world"}',
                "data: [DONE]",
            ]
        )
        text, response_id = common._stream_response_events(raw)
        self.assertEqual(text, "hello world")
        self.assertEqual(response_id, "resp_test_1")

    def test_responses_text_with_meta_reuses_and_updates_context_non_stream(self) -> None:
        captured_payloads: list[dict[str, object]] = []

        def _fake_create(_base_url: str, _api_key: str, payload: dict[str, object], timeout: int = 120) -> dict[str, object]:
            del timeout
            captured_payloads.append(dict(payload))
            return {"id": "resp_test_2", "output_text": "ok"}

        context = {"previous_response_id": "resp_prev"}
        with patch("rag.common._responses_force_stream", return_value=False), patch("rag.common.responses_create", side_effect=_fake_create):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "hello"}],
                response_context=context,
            )
        self.assertEqual(text, "ok")
        self.assertIs(out_ctx, context)
        self.assertEqual(context["previous_response_id"], "resp_test_2")
        self.assertTrue(captured_payloads)
        self.assertEqual(captured_payloads[-1].get("previous_response_id"), "resp_prev")

    def test_responses_text_with_meta_updates_context_stream(self) -> None:
        context = {"previous_response_id": "resp_prev"}
        with patch("rag.common._responses_force_stream", return_value=True), patch(
            "rag.common._responses_text_stream",
            return_value=("stream-ok", "resp_test_3"),
        ):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "hello"}],
                response_context=context,
            )
        self.assertEqual(text, "stream-ok")
        self.assertIs(out_ctx, context)
        self.assertEqual(context["previous_response_id"], "resp_test_3")

    def test_responses_text_with_meta_disables_prev_id_after_failure(self) -> None:
        calls: list[dict[str, object]] = []

        def _fake_create(_base_url: str, _api_key: str, payload: dict[str, object], timeout: int = 120) -> dict[str, object]:
            del timeout
            calls.append(dict(payload))
            if "previous_response_id" in payload:
                raise RuntimeError("HTTP 400 from /responses: bad request")
            return {"id": "resp_fallback_ok", "output_text": "ok"}

        context = {"previous_response_id": "resp_prev"}
        with patch("rag.common._responses_force_stream", return_value=False), patch("rag.common.responses_create", side_effect=_fake_create):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "hello"}],
                response_context=context,
            )
        self.assertEqual(text, "ok")
        self.assertIs(out_ctx, context)
        self.assertEqual(context["previous_response_id"], "resp_fallback_ok")
        self.assertTrue(context["disable_previous_response_id"])
        self.assertEqual(len(calls), 2)
        self.assertIn("previous_response_id", calls[0])
        self.assertNotIn("previous_response_id", calls[1])

    def test_responses_text_with_meta_replays_history_after_prev_id_failure(self) -> None:
        calls: list[dict[str, object]] = []

        def _fake_create(_base_url: str, _api_key: str, payload: dict[str, object], timeout: int = 120) -> dict[str, object]:
            del timeout
            calls.append(dict(payload))
            if "previous_response_id" in payload:
                raise RuntimeError("HTTP 400 from /responses: bad request")
            return {"id": "resp_ok_after_replay", "output_text": "ok"}

        context = {"previous_response_id": "resp_prev"}
        with patch("rag.common._responses_force_stream", return_value=False), patch("rag.common.responses_create", side_effect=_fake_create):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "hello"}],
                response_context=context,
            )
        self.assertEqual(text, "ok")
        self.assertIs(out_ctx, context)
        self.assertTrue(context["disable_previous_response_id"])
        self.assertEqual(
            context["replay_messages"],
            [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "ok"},
            ],
        )
        self.assertEqual(len(calls), 2)
        self.assertIn("previous_response_id", calls[0])
        self.assertNotIn("previous_response_id", calls[1])

    def test_responses_text_with_meta_uses_replay_messages_when_prev_disabled(self) -> None:
        calls: list[dict[str, object]] = []

        def _fake_create(_base_url: str, _api_key: str, payload: dict[str, object], timeout: int = 120) -> dict[str, object]:
            del timeout
            calls.append(dict(payload))
            return {"id": "resp_replay_2", "output_text": "next"}

        context = {
            "previous_response_id": "resp_prev",
            "disable_previous_response_id": True,
            "replay_messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "ok"},
            ],
        }
        with patch("rag.common._responses_force_stream", return_value=False), patch("rag.common.responses_create", side_effect=_fake_create):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "again"}],
                response_context=context,
            )
        self.assertEqual(text, "next")
        self.assertIs(out_ctx, context)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("previous_response_id", calls[0])
        self.assertEqual(
            calls[0]["input"],
            [
                {"role": "user", "content": [{"type": "input_text", "text": "hello"}]},
                {"role": "assistant", "content": [{"type": "output_text", "text": "ok"}]},
                {"role": "user", "content": [{"type": "input_text", "text": "again"}]},
            ],
        )
        self.assertEqual(
            context["replay_messages"],
            [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "again"},
                {"role": "assistant", "content": "next"},
            ],
        )

    def test_responses_text_with_meta_prefers_local_msgchain_over_previous_id(self) -> None:
        calls: list[dict[str, object]] = []

        def _fake_create(_base_url: str, _api_key: str, payload: dict[str, object], timeout: int = 120) -> dict[str, object]:
            del timeout
            calls.append(dict(payload))
            return {"id": "resp_local_chain", "output_text": "LOCAL_OK"}

        context = {
            "previous_response_id": "resp_prev_should_not_be_used",
            "use_local_msgchain": True,
            "replay_messages": [
                {"role": "user", "content": "seed"},
                {"role": "assistant", "content": "seed_ok"},
            ],
        }
        with patch("rag.common._responses_force_stream", return_value=False), patch("rag.common.responses_create", side_effect=_fake_create):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "next"}],
                response_context=context,
            )
        self.assertEqual(text, "LOCAL_OK")
        self.assertIs(out_ctx, context)
        self.assertTrue(context["use_local_msgchain"])
        self.assertEqual(context["previous_response_id"], "resp_local_chain")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("previous_response_id", calls[0])
        self.assertEqual(
            calls[0]["input"],
            [
                {"role": "user", "content": [{"type": "input_text", "text": "seed"}]},
                {"role": "assistant", "content": [{"type": "output_text", "text": "seed_ok"}]},
                {"role": "user", "content": [{"type": "input_text", "text": "next"}]},
            ],
        )

    def test_local_msgchain_overflow_archives_to_long_term_memory(self) -> None:
        calls: list[dict[str, object]] = []

        def _fake_create(_base_url: str, _api_key: str, payload: dict[str, object], timeout: int = 120) -> dict[str, object]:
            del timeout
            calls.append(dict(payload))
            return {"id": "resp_archive_1", "output_text": "ack"}

        context = {
            "use_local_msgchain": True,
            "replay_messages": [
                {"role": "user", "content": "seed one alpha"},
                {"role": "assistant", "content": "ok one"},
                {"role": "user", "content": "seed two beta"},
                {"role": "assistant", "content": "ok two"},
                {"role": "user", "content": "seed three gamma"},
                {"role": "assistant", "content": "ok three"},
                {"role": "user", "content": "seed four delta"},
                {"role": "assistant", "content": "ok four"},
            ],
        }
        with patch("rag.common._responses_force_stream", return_value=False), patch(
            "rag.common.responses_create", side_effect=_fake_create
        ), patch.dict("os.environ", {"OPENAI_REPLAY_MAX_MESSAGES": "8"}, clear=False):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "new turn gamma"}],
                response_context=context,
            )
        self.assertEqual(text, "ack")
        self.assertIs(out_ctx, context)
        self.assertEqual(len(context["replay_messages"]), 8)
        self.assertTrue(isinstance(context.get("long_term_memory", []), list))
        self.assertGreaterEqual(len(context["long_term_memory"]), 1)

    def test_long_term_recall_injected_as_system_message(self) -> None:
        calls: list[dict[str, object]] = []

        def _fake_create(_base_url: str, _api_key: str, payload: dict[str, object], timeout: int = 120) -> dict[str, object]:
            del timeout
            calls.append(dict(payload))
            return {"id": "resp_recall_1", "output_text": "recalled"}

        context = {
            "use_local_msgchain": True,
            "replay_messages": [],
            "long_term_memory": [
                {"summary": "user asked marker zeta-31415 and confirmed it", "keywords": ["marker", "zeta-31415", "confirmed"]},
                {"summary": "tested login flow with admin cookie", "keywords": ["login", "admin", "cookie"]},
            ],
        }
        with patch("rag.common._responses_force_stream", return_value=False), patch("rag.common.responses_create", side_effect=_fake_create):
            text, out_ctx = common.responses_text_with_meta(
                base_url="http://example.local/v1",
                api_key="x",
                model="gpt-5.4",
                messages=[{"role": "user", "content": "what is the marker value?"}],
                response_context=context,
            )
        self.assertEqual(text, "recalled")
        self.assertIs(out_ctx, context)
        self.assertEqual(len(calls), 1)
        req_input = calls[0]["input"]
        self.assertTrue(isinstance(req_input, list) and len(req_input) >= 2)
        self.assertEqual(req_input[0]["role"], "system")
        self.assertIn("Long-term memory recall", req_input[0]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
