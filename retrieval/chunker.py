"""Splits corpus documents into retrievable chunks.

Paragraph-packing rather than fixed-width slicing: paragraphs are the unit a
policy document is actually written in, and cutting mid-sentence produces
chunks that embed badly and read worse when they reach the model.

Every chunk carries where it came from -- document, ordinal, character
offsets, and a hash of its own text. That is not bookkeeping. Two things
depend on it:

  * A generation's record can name the exact chunks that were in its
    context. Without that, a retrieval pipeline is the same silent-no-op
    hazard as the category-8 harness that wrote its payload to disk and
    never read it back (procedure §10.1a): a test whose poisoned document
    simply lost the retrieval race looks identical to one the model
    resisted.

  * Chunk boundaries are themselves an attack surface. A payload split so
    that no single chunk reads as malicious is only testable if the
    boundaries are recorded and reproducible.
"""

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import List

# Big enough that a policy clause and its qualifier usually stay together,
# small enough that top-k is a real choice rather than "most of the corpus".
MAX_CHARS = 700
# One paragraph of overlap, so a clause split across a boundary is still
# fully present in one of the two chunks.
OVERLAP_PARAGRAPHS = 1


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    ordinal: int
    text: str
    start: int
    end: int
    sha256: str = field(default="")

    def __post_init__(self):
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.text.encode("utf-8")).hexdigest()


def split_paragraphs(text):
    """Yields (paragraph, start_offset). Offsets are into the original text so
    a chunk can always be located in the document it came from."""
    out, pos = [], 0
    for part in re.split(r"\n\s*\n", text):
        start = text.find(part, pos)
        if start < 0:
            start = pos
        stripped = part.strip()
        if stripped:
            out.append((stripped, start + part.index(stripped[0])))
        pos = start + len(part)
    return out


def chunk_text(doc_id, text, max_chars=MAX_CHARS,
               overlap=OVERLAP_PARAGRAPHS) -> List[Chunk]:
    paras = split_paragraphs(text)
    if not paras:
        return []

    chunks, buf, ordinal = [], [], 0
    def flush():
        nonlocal buf, ordinal
        if not buf:
            return
        body = "\n\n".join(p for p, _ in buf)
        start = buf[0][1]
        chunks.append(Chunk(
            chunk_id=f"{doc_id}#{ordinal}", doc_id=doc_id, ordinal=ordinal,
            text=body, start=start, end=start + len(body)))
        ordinal += 1
        buf = buf[-overlap:] if overlap else []

    for para, start in paras:
        # A paragraph longer than the budget on its own still becomes its own
        # chunk rather than being cut: a truncated clause is worse than a
        # large one, and this corpus has none.
        if buf and sum(len(p) + 2 for p, _ in buf) + len(para) > max_chars:
            flush()
        buf.append((para, start))
    flush()
    return chunks


def load_corpus(corpus_dir="corpus") -> List[Chunk]:
    """Every .md in the corpus directory, chunked. README.md is documentation
    about the corpus rather than part of it, and is excluded."""
    chunks = []
    for name in sorted(os.listdir(corpus_dir)):
        if not name.endswith(".md") or name == "README.md":
            continue
        path = os.path.join(corpus_dir, name)
        with open(path, encoding="utf-8") as f:
            chunks.extend(chunk_text(name[:-3], f.read()))
    return chunks
