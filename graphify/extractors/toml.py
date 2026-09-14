"""TOML AST extractor for graphify. Parses TOML files using tree-sitter-toml.

Extracts table sections and key-value pairs as concept nodes.
Sections are linked to their parent file. Secrets are redacted.
"""
from __future__ import annotations

from pathlib import Path

from graphify.extractors.base import _file_stem, _make_id, _read_text

# Try to import tree-sitter-toml; if missing, the extractor is a no-op.
try:
    from tree_sitter import Language, Parser

    _TOML_LANG = Language(  # type: ignore
        __import__("tree_sitter_toml", fromlist=["language"]).language()
    )
    _HAS_TOML = True
except Exception:
    _HAS_TOML = False

# Sensitive key patterns (shared with yaml.py)
_SENSITIVE_KEY_SUFFIXES = frozenset({
    "password", "secret", "token", "api_key", "apikey", "auth_token",
    "access_key", "secret_key", "private_key", "ssh_key",
    "connection_string", "signing_key", "encryption_key", "master_key",
    "license_key", "pat", "bearer", "jwt", "refresh_token",
})


def _is_sensitive_key(key: str) -> bool:
    lower = key.lower().replace("_", " ").replace("-", " ")
    for suffix in _SENSITIVE_KEY_SUFFIXES:
        s = suffix.lower().replace("_", " ").replace("-", " ")
        if s in lower:
            return True
    return False


def _redact_value(key: str, value: str) -> str:
    """Return the value or __REDACTED__ if the key/value looks sensitive."""
    if not value or len(value) < 20:
        return value
    if _is_sensitive_key(key):
        return "__REDACTED__"
    # Check for sops-encrypted values
    if value.startswith("ENC[") or value.startswith("sops:"):
        return "__REDACTED__"
    return value


def extract_toml(path: Path, *, content: bytes | None = None) -> dict:
    """Extract nodes and edges from a TOML file using tree-sitter-toml.

    Returns a dict with keys: nodes, edges.
    """
    if not _HAS_TOML:
        raise ImportError(
            "tree-sitter-toml not installed. "
            'Install it with: pip install "graphifyy[toml]"'
        )

    try:
        source = content if content is not None else path.read_bytes()
    except Exception:
        return {"nodes": [], "edges": []}

    nodes: list[dict] = []
    edges: list[dict] = []

    try:
        parser = Parser()
        parser.language = _TOML_LANG
        tree = parser.parse(source)
    except Exception:
        return {"nodes": [], "edges": []}

    root = tree.root_node

    # File-level node
    stem = _file_stem(path)
    file_nid = _make_id(stem, path.name.split(".")[0])
    nodes.append({
        "id": file_nid,
        "label": path.name,
        "file_type": "code",
        "source_file": str(path),
        "source_location": "L1",
    })

    # Walk the document for tables and key-value pairs
    for child in root.children:
        if child.type == "table":
            # Extract table name from bracket notation
            table_text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace").strip()
            table_name = table_text.strip("[]").strip()
            if not table_name:
                continue

            start_line = child.start_point[0] + 1
            tid = _make_id(stem, path.name.split(".")[0], "table", table_name.replace(".", "-"))

            nodes.append({
                "id": tid,
                "label": table_name,
                "file_type": "code",
                "source_file": str(path),
                "source_location": f"L{start_line}",
            })
            edges.append({
                "source": file_nid,
                "target": tid,
                "relation": "contains",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": str(path),
                "source_location": f"L{start_line}",
            })

            # Extract key-value pairs under this table
            for pair in child.children:
                if pair.type == "pair":
                    key_text = ""
                    val_text = ""
                    for c in pair.children:
                        if c.type == "key":
                            key_text = _read_text(c, source).strip().strip('"').strip("'")
                        elif c.type in ("string", "integer", "float", "boolean", "bare_key", "quoted_key", "inline_table", "array"):
                            val_text = _read_text(c, source).strip().strip('"').strip("'")

                    if key_text:
                        val_text = _redact_value(key_text, val_text)
                        if val_text:
                            kid = _make_id(tid, key_text.replace(".", "-"))

                            nodes.append({
                                "id": kid,
                                "label": f"{table_name}.{key_text}",
                                "file_type": "code",
                                "source_file": str(path),
                                "source_location": f"L{pair.start_point[0] + 1}",
                            })
                            edges.append({
                                "source": tid,
                                "target": kid,
                                "relation": "contains",
                                "confidence": "EXTRACTED",
                                "confidence_score": 1.0,
                                "source_file": str(path),
                                "source_location": f"L{pair.start_point[0] + 1}",
                            })

        elif child.type == "pair":
            # Top-level key-value pairs (not in a table)
            key_text = ""
            val_text = ""
            for c in child.children:
                if c.type == "key":
                    key_text = _read_text(c, source).strip().strip('"').strip("'")
                elif c.type in ("string", "integer", "float", "boolean"):
                    val_text = _read_text(c, source).strip().strip('"').strip("'")

            if key_text:
                val_text = _redact_value(key_text, val_text)
                if val_text:
                    pid = _make_id(stem, path.name.split(".")[0], key_text.replace(".", "-"))
                    nodes.append({
                        "id": pid,
                        "label": key_text,
                        "file_type": "code",
                        "source_file": str(path),
                        "source_location": f"L{child.start_point[0] + 1}",
                    })
                    edges.append({
                        "source": file_nid,
                        "target": pid,
                        "relation": "contains",
                        "confidence": "EXTRACTED",
                        "confidence_score": 1.0,
                        "source_file": str(path),
                        "source_location": f"L{child.start_point[0] + 1}",
                    })

    if not edges:
        return {"nodes": [], "edges": []}

    return {"nodes": nodes, "edges": edges}