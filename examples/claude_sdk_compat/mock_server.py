"""Local synthetic Anthropic-format server. No upstream network requests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading


class MockServer:
    def __init__(self):
        self.observations = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                if "count_tokens" in self.path:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"input_tokens": 20}')
                    return
                if self.path.split("?")[0] != "/v1/messages":
                    self.send_error(404)
                    return
                owner.observations.append({
                    "path": "/v1/messages", "tools_count": len(body.get("tools") or []),
                    "stream": bool(body.get("stream")),
                })
                prompt = json.dumps(body.get("messages", []))
                answer = '{"total":5,"unit":"books"}' if "DEMO_JSON" in prompt else "SDK_DEMO_OK"
                usage = {"input_tokens": 20, "output_tokens": 10}
                message = {"id": "msg_mock", "type": "message", "role": "assistant",
                           "model": body.get("model"), "content": [{"type": "text", "text": answer}],
                           "stop_reason": "end_turn", "stop_sequence": None, "usage": usage}
                self.send_response(200)
                if body.get("stream"):
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    start = {**message, "content": [], "stop_reason": None}
                    events = [
                        {"type": "message_start", "message": start},
                        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": answer}},
                        {"type": "content_block_stop", "index": 0},
                        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 10}},
                        {"type": "message_stop"},
                    ]
                    for event in events:
                        self.wfile.write(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode())
                    self.wfile.flush()
                else:
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(message).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
