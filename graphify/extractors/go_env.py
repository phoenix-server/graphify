"""Go environment variable name extractor. Finds env var names in Go string literals.

Walks a Go file's AST for call_expression nodes where the callee is a known
env-var access function (os.Getenv, os.LookupEnv, viper.GetString, Env(), ...)
and extracts the first string argument as the env var name.
"""
from __future__ import annotations

import re
from pathlib import Path

from graphify.extractors.base import _file_stem, _make_id

# Call patterns that access environment variables.
# Each entry: (callee_name_substring, is_selector, selector_field_name)
_ENV_CALL_PATTERNS: list[tuple[str, bool, str | None]] = [
    # os.Getenv, os.LookupEnv
    ("Getenv", True, None),      # Callee is a selector_expression, field name matches
    ("LookupEnv", True, None),
    # viper.GetString, viper.GetInt, etc.
    ("GetString", True, None),
    ("GetInt", True, None),
    ("GetBool", True, None),
    ("GetFloat64", True, None),
    ("GetDuration", True, None),
    # Standalone functions
    ("Env", False, None),
    ("Environment", False, None),
]

# Regex to check for selector_expression calls (Package.FuncName).
_SELECTOR_RX = re.compile(r"(?:os|viper|env|config|cfg|settings)")


def _is_env_call(node_type: str, callee_text: str) -> bool:
    """Check if a Go call_expression callee matches an env-var access pattern."""
    if node_type == "identifier":
        # Bare call: Env("VAR")
        for name, is_selector, _ in _ENV_CALL_PATTERNS:
            if not is_selector and callee_text.lower() == name.lower():
                return True
        return False
    if node_type == "selector_expression":
        # Selector: os.Getenv("VAR")
        # Extract the field (function name)
        for name, is_selector, _ in _ENV_CALL_PATTERNS:
            if is_selector:
                # Check if the callee text ends with the function name
                # e.g., "os.Getenv" ends with "Getenv"
                if callee_text.lower().endswith(name.lower()):
                    return True
        return False
    return False


def extract_go_env(path: Path, *, source_override: bytes | None = None) -> dict:
    """Extract environment variable names from Go code.

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

    found_vars: dict[str, int] = {}

    def walk_calls(node) -> None:
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node is None:
                return
            callee_text = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
            if not _is_env_call(func_node.type, callee_text):
                return
            # First string argument is the env var name.
            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                return
            for child in args_node.children:
                if child.type in ("interpreted_string_literal", "raw_string_literal"):
                    raw = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                    # Strip quotes.
                    content = raw.strip()
                    if content.startswith(("'", '"', "`")):
                        content = content[1:]
                    if content.endswith(("'", '"', "`")):
                        content = content[:-1]
                    content = content.strip()
                    if content and len(content) >= 2:
                        line = source[: child.start_byte].count(b"\n") + 1
                        if content not in found_vars:
                            found_vars[content] = line
                    break  # Only first string arg.

        for child in node.children:
            walk_calls(child)

    walk_calls(go_root)

    for var_name, first_line in found_vars.items():
        var_nid = _make_id(var_name)
        nodes.append({
            "id": var_nid,
            "label": var_name,
            "file_type": "code",
            "source_file": str_path,
            "source_location": f"L{first_line}",
            "_origin": "go_env_literal",
        })
        edges.append({
            "source": file_nid,
            "target": var_nid,
            "relation": "contains",
            "confidence": "EXTRACTED",
            "context": "env_literal",
            "source_file": str_path,
            "source_location": f"L{first_line}",
            "weight": 1.0,
        })

    return {"nodes": nodes, "edges": edges}