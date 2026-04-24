from __future__ import annotations

import unittest
from unittest.mock import patch

from rag.agent import hybrid_retrieve
from rag.query import retrieve


class RetrievalFallbackTests(unittest.TestCase):
    def test_hybrid_retrieve_degrades_to_bm25_when_embeddings_fail(self) -> None:
        docs = [
            {"text": "flag poem traversal", "embedding": [1.0, 0.0], "path": "a", "chunk_index": 0},
            {"text": "login auth session", "embedding": [0.0, 1.0], "path": "b", "chunk_index": 1},
        ]
        with patch("rag.agent.embed_texts", side_effect=RuntimeError("embeddings unsupported")):
            hits = hybrid_retrieve(
                query="poem traversal",
                docs=docs,
                top_k=2,
                mode="hybrid",
                alpha=0.65,
                base_url="http://example.local/v1",
                api_key="x",
                embed_model="text-embedding-3-small",
            )
        self.assertEqual(hits[0]["path"], "a")
        self.assertGreaterEqual(hits[0]["bm25_score"], hits[1]["bm25_score"])

    def test_query_retrieve_degrades_to_bm25_when_question_embedding_missing(self) -> None:
        docs = [
            {"text": "flag poem traversal", "embedding": [1.0, 0.0], "path": "a", "chunk_index": 0},
            {"text": "login auth session", "embedding": [0.0, 1.0], "path": "b", "chunk_index": 1},
        ]
        hits = retrieve(
            question="poem traversal",
            docs=docs,
            top_k=2,
            mode="hybrid",
            alpha=0.65,
            question_embedding=None,
            bm25_k1=1.5,
            bm25_b=0.75,
        )
        self.assertEqual(hits[0]["path"], "a")
        self.assertGreaterEqual(hits[0]["bm25_score"], hits[1]["bm25_score"])


if __name__ == "__main__":
    unittest.main()
