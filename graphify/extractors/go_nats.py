"""Go NATS subject extractor. Finds NATS subject patterns in Go string literals.

Walks a Go file's AST for string literal arguments to known NATS operations
(Subscribe, Publish, QueueSubscribe, AddConsumer, etc.) and extracts the
subject pattern. Emits edges classified as ``publishes_to`` or ``subscribes_to``
based on the operation type.
"""
from __future__ import annotations

import re
from pathlib import Path

from graphify.extractors.base import _file_stem, _make_id

# NATS subject patterns: alphanumeric segments separated by dots, with wildcards
# `*` (single token) or `>` (multi-token tail). Colons used as separators too.
_SUBJECT_RX = re.compile(
    r"[a-zA-Z][a-zA-Z0-9_.:>*-]+"
)

# NATS function/keyword patterns for classifying operations.
_SUBSCRIBE_FUNCS = frozenset({
    "subscribe", "queuesubscribe", "sub",
    "addconsumer", "consumebind",
})
_PUBLISH_FUNCS = frozenset({
    "publish", "queuepublish", "request", "pub",
    "requestmsg", "publishmsg",
})

# Detect subject-like patterns: must contain at least one `.` or `:` separator
# to distinguish from plain variable names or non-subject strings.
_SUBJECT_SEPARATOR_RX = re.compile(r"[.:]")


def _is_nats_call(callee_type: str, callee_text: str) -> str | None:
    """Check if a Go call_expression is a NATS operation.

    Returns ``"subscribe"``, ``"publish"``, or ``None``.
    """
    name = callee_text.lower()
    # Extract the last segment from a selector expression (e.g. ``js.Publish`` -> ``publish``)
    if callee_type == "selector_expression":
        # ``js.Publish`` -> last segment is ``Publish``
        name = name.split(".")[-1] if "." in name else name
    elif callee_type != "identifier":
        return None

    if name in _SUBSCRIBE_FUNCS:
        return "subscribe"
    if name in _PUBLISH_FUNCS:
        return "publish"
    return None


def _looks_like_subject(text: str) -> bool:
    """Heuristic: a string looks like a NATS subject if it contains separators.

    Filters out Go import paths (contain ``github.com/``, ``gitlab.com/``, etc.)
    and URL-like patterns (``://`` or ``http``).
    """
    if not _SUBJECT_SEPARATOR_RX.search(text) or len(text) < 3:
        return False
    # Reject Go import paths.
    if re.search(r"(?:github\.com|gitlab\.com|bitbucket\.org|gopkg\.in)\b", text, re.I):
        return False
    # Reject URLs.
    if "://" in text or text.startswith(("http:", "https:", "nats://")):
        return False
    return True


def extract_go_nats(path: Path, *, source_override: bytes | None = None) -> dict:
    """Extract NATS subject references from Go code.

    Returns a graph extraction dict with ``nodes`` and ``edges`` lists.
    """
    if source_override is not None:
        source = source_override
    else:
        source = path.read_bytes()

    str_path = str(path)
    stem = _file_stem(path)
    file_nid = _make_id(stem)

    nodes: list[dict] = []
    edges: list[dict] = []

    try:
        import tree_sitter_go as tsgo
        from tree_sitter import Language, Parser
    except ImportError:
        return {"nodes": [], "edges": []}

    go_parser = Parser(Language(tsgo.language()))
    go_tree = go_parser.parse(source)
    go_root = go_tree.root_node

    found_subjects: dict[str, tuple[int, str]] = {}  # subject -> (line, operation)

    def walk_calls(node) -> None:
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node is None:
                return
            callee_text = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
            operation = _is_nats_call(func_node.type, callee_text)
            if operation is None:
                # Still check string arguments for subject patterns — some
                # NATS operations use variable callees or different patterns.
                pass
            else:
                args_node = node.child_by_field_name("arguments")
                if args_node is None:
                    return
                # Scan all string arguments for subject-like patterns.
                for child in args_node.children:
                    if child.type in ("interpreted_string_literal", "raw_string_literal"):
                        raw = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                        content = raw.strip()
                        if content.startswith(("'", '"', "`")):
                            content = content[1:]
                        if content.endswith(("'", '"', "`")):
                            content = content[:-1]
                        content = content.strip()
                        if _looks_like_subject(content):
                            line = source[: child.start_byte].count(b"\n") + 1
                            if content not in found_subjects:
                                found_subjects[content] = (line, operation)

        for child in node.children:
            walk_calls(child)

    # Also scan ALL string literals for subject patterns, even outside
    # known NATS calls (subjects may be stored in variables before being passed).
    def walk_strings(node) -> None:
        if node.type in ("interpreted_string_literal_content", "raw_string_literal_content"):
            raw = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            if _looks_like_subject(raw):
                line = source[: node.start_byte].count(b"\n") + 1
                if raw not in found_subjects:
                    found_subjects[raw] = (line, "unknown")

        for child in node.children:
            walk_strings(child)

    walk_calls(go_root)
    walk_strings(go_root)

    for subject, (first_line, operation) in found_subjects.items():
        subj_nid = _make_id(subject)
        nodes.append({
            "id": subj_nid,
            "label": subject,
            "file_type": "code",
            "source_file": str_path,
            "source_location": f"L{first_line}",
            "_origin": "go_nats_subject",
        })
        rel = operation if operation in ("publish", "subscribe") else "references"
        if operation == "unknown":
            rel = "references"
        elif operation == "publish":
            rel = "publishes_to"
        else:
            rel = f"{operation}s_to"
        edges.append({
            "source": file_nid,
            "target": subj_nid,
            "relation": rel,
            "confidence": "EXTRACTED",
            "context": f"nats_{operation}",
            "source_file": str_path,
            "source_location": f"L{first_line}",
            "weight": 1.0,
        })

    return {"nodes": nodes, "edges": edges}