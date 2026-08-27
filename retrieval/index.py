"""Embeds the corpus and answers top-k queries over it.

No vector database. At this corpus size the whole index is a few hundred
floats per chunk held in a list, and a database would add operational
surface without adding any of the security surface this project studies.

`nomic-embed-text` is reused rather than introducing a second embedding
model: `detection/injection_filter_output.py` already embeds with it for its
system-prompt similarity signal, and one model means one thing to have
installed and one set of vectors to reason about.

Embeddings are cached to disk keyed by the chunk's own content hash, so
re-running costs nothing unless a document actually changed -- and a changed
document invalidates exactly its own chunks, not the whole index.
"""

import io
import json
import math
import os
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from retrieval.chunker import Chunk, load_corpus  # noqa: E402

EMBED_MODEL = "nomic-embed-text"
CACHE_PATH = os.path.join("evaluation", ".embed_cache.json")


@dataclass
class Hit:
    chunk: Chunk
    score: float


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    num = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return num / (na * nb) if na and nb else 0.0


class CorpusIndex:
    def __init__(self, client=None, corpus_dir="corpus", cache_path=CACHE_PATH):
        import ollama
        self.client = client or ollama.Client(timeout=120)
        self.chunks: List[Chunk] = load_corpus(corpus_dir)
        self.cache_path = cache_path
        self._cache = self._load_cache()
        self.vectors: List[List[float]] = []

    def _load_cache(self):
        try:
            return json.loads(io.open(self.cache_path, encoding="utf-8").read())
        except (OSError, ValueError):
            return {}

    def _save_cache(self):
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        io.open(self.cache_path, "w", encoding="utf-8", newline="\n").write(
            json.dumps(self._cache))

    def embed(self, text: str) -> List[float]:
        return self.client.embeddings(
            model=EMBED_MODEL, prompt=text, keep_alive="60m")["embedding"]

    def build(self, verbose=False):
        fresh = 0
        for c in self.chunks:
            vec = self._cache.get(c.sha256)
            if vec is None:
                vec = self.embed(c.text)
                self._cache[c.sha256] = vec
                fresh += 1
            self.vectors.append(vec)
        if fresh:
            self._save_cache()
        if verbose:
            print(f"index: {len(self.chunks)} chunks from "
                  f"{len({c.doc_id for c in self.chunks})} documents "
                  f"({fresh} newly embedded, {len(self.chunks)-fresh} cached)",
                  file=sys.stderr)
        return self

    def search(self, query: str, k: int = 4,
               allow: Optional[set] = None) -> List[Hit]:
        """Top-k by cosine similarity.

        `allow` restricts the candidate set to those chunk ids. It exists for
        the access-control work: filtering at retrieval means a record that
        must not be disclosed is never in the context to begin with, which is
        a stronger property than asking the model not to repeat it. It is not
        used yet -- the employee records are still passed whole (see
        ROADMAP), and wiring it is a separate, measured step.
        """
        qv = self.embed(query)
        scored = [
            Hit(c, cosine(qv, v))
            for c, v in zip(self.chunks, self.vectors)
            if allow is None or c.chunk_id in allow
        ]
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:k]
