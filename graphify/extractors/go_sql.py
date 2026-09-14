"""Go SQL string literal extractor. Finds SQL table references in Go string literals.

Walks a Go file's AST for interpreted_string_literal and raw_string_literal nodes,
checks their content for SQL statements (INSERT, SELECT, CREATE TABLE, etc.),
parses the SQL with tree-sitter-sql, and emits table-reference nodes/edges.
"""
from __future__ import annotations

import re
from pathlib import Path

from graphify.extractors.base import _file_stem, _make_id

# Quick regex to detect SQL in a string literal before full parse.
_SQL_KEYWORD_RX = re.compile(
    r"\b(?:INSERT\s+INTO|SELECT\s+|CREATE\s+TABLE|DELETE\s+FROM|UPDATE\s+|"
    r"ALTER\s+TABLE|DROP\s+TABLE|TRUNCATE|MERGE\s+INTO|REPLACE\s+INTO)",
    re.IGNORECASE,
)

# Tables named with known SQL keywords or common CTE names are not real tables.
_NON_TABLE_IDENTS = frozenset({
    # CTE / subquery aliases the SQL parser may misidentify
    "t", "x", "y", "temp", "tmp", "cte", "sub", "subquery",
    # Pseudo-tables from SQL-based frameworks
    "dual", "pg_catalog", "information_schema",
})


def _is_likely_sql(text: str) -> bool:
    """Quick heuristic: does the string look like it contains SQL?"""
    # Skip very short strings (must contain a keyword).
    if len(text) < 10:
        return False
    return bool(_SQL_KEYWORD_RX.search(text))


def _table_name_from_ref(ref_text: str) -> str | None:
    """Extract a clean table name from an object_reference text.

    Handles quoted identifiers and schema-qualified names like ``public.users``.
    Returns the last segment (unqualified table name).
    """
    ref = ref_text.strip().strip('"').strip("`").strip("'").strip("[]")
    # Schema-qualified: ``public.users`` -> ``users``
    parts = ref.split(".")
    if len(parts) > 1:
        return parts[-1].strip()
    return ref if ref else None


def _extract_table_refs(sql_text: str) -> list[tuple[str, int]]:
    """Parse SQL text with tree-sitter-sql and return (table_name, line_in_sql) pairs.

    Only extracts object_references that are genuine table references —
    column references and aliases inside SELECT expressions are ignored.
    """
    try:
        import tree_sitter_sql as tssql
        from tree_sitter import Language, Parser
    except ImportError:
        return []

    parser = Parser(Language(tssql.language()))
    source = sql_text.encode("utf-8")
    tree = parser.parse(source)
    root = tree.root_node

    seen: set[str] = set()
    refs: list[tuple[str, int]] = []

    def _walk(node) -> None:
        if node.type == "relation":
            # Direct child object_reference of relation = table name
            for c in node.children:
                if c.type == "object_reference":
                    text = source[c.start_byte : c.end_byte].decode("utf-8", errors="replace")
                    name = _table_name_from_ref(text)
                    if name and name.lower() not in _NON_TABLE_IDENTS and name not in seen:
                        seen.add(name)
                        line = source[: c.start_byte].count(b"\n")
                        refs.append((name, line + 1))
                    break  # Only the first child is the table; rest are aliases.
        # Also look for object_reference in insert/delete/update/create targets.
        if node.type in ("insert", "delete", "update", "create_table", "create_view", "create_index", "create_trigger"):
            for c in node.children:
                if c.type == "object_reference":
                    text = source[c.start_byte : c.end_byte].decode("utf-8", errors="replace")
                    name = _table_name_from_ref(text)
                    if name and name.lower() not in _NON_TABLE_IDENTS and name not in seen:
                        seen.add(name)
                        line = source[: c.start_byte].count(b"\n")
                        refs.append((name, line + 1))
        for child in node.children:
            _walk(child)

    _walk(root)
    return refs


SQL_CACHE: dict[str, list[tuple[str, int]]] = {}


def extract_go_sql(path: Path, *, source_override: bytes | None = None) -> dict:
    """Extract SQL table references from Go string literals.

    Returns a graph extraction dict with ``nodes`` and ``edges`` lists,
    compatible with graphify's extraction format.
    """
    if source_override is not None:
        source = source_override
    else:
        source = path.read_bytes()

    str_path = str(path)
    stem = _file_stem(path)
    file_nid = _make_id(stem)
    lines = source.decode("utf-8", errors="replace").split("\n")

    nodes: list[dict] = []
    edges: list[dict] = []

    # Common SQL operations that indicate a table reference
    sql_ops = {"insert_into", "select_from", "delete_from", "update", "create_table"}

    try:
        import tree_sitter_go as tsgo
        from tree_sitter import Language, Parser
    except ImportError:
        return {"nodes": [], "edges": []}

    go_parser = Parser(Language(tsgo.language()))
    go_tree = go_parser.parse(source)
    go_root = go_tree.root_node

    # Walk the Go AST for string literal content nodes.
    pending: list[tuple[bytes | str, int]] = []  # (content, line offset)

    def walk_strings(node) -> None:
        if node.type in ("interpreted_string_literal_content", "raw_string_literal_content"):
            content = source[node.start_byte : node.end_byte]
            line = source[: node.start_byte].count(b"\n")
            pending.append((content, line + 1))
        for child in node.children:
            walk_strings(child)

    walk_strings(go_root)

    tables_found: dict[str, int] = {}  # table_name -> first line in go file

    for content_bytes, go_line in pending:
        text = content_bytes.decode("utf-8", errors="replace")
        if not _is_likely_sql(text):
            continue

        # De-duplicate by caching full-text per unique SQL string.
        cache_key = text.strip().lower()
        if cache_key in SQL_CACHE:
            refs = SQL_CACHE[cache_key]
        else:
            refs = _extract_table_refs(text)
            SQL_CACHE[cache_key] = refs

        for tbl_name, _ in refs:
            if tbl_name not in tables_found:
                tables_found[tbl_name] = go_line

    # Emit nodes and edges.
    for tbl_name, first_line in tables_found.items():
        tbl_nid = _make_id(tbl_name)
        nodes.append({
            "id": tbl_nid,
            "label": tbl_name,
            "file_type": "code",
            "source_file": str_path,
            "source_location": f"L{first_line}",
            "_origin": "go_sql_literal",
        })
        edges.append({
            "source": file_nid,
            "target": tbl_nid,
            "relation": "contains",
            "confidence": "EXTRACTED",
            "context": "sql_literal",
            "source_file": str_path,
            "source_location": f"L{first_line}",
            "weight": 1.0,
        })

    return {"nodes": nodes, "edges": edges}