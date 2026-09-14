"""Protobuf extractor. Extracts services, RPC methods, and message types from .proto files.

Uses regex-based parsing since the protobuf grammar has a simple, predictable
structure that doesn't require a full tree-sitter parser.
"""
from __future__ import annotations

import re
from pathlib import Path

from graphify.extractors.base import _file_stem, _make_id

# Service definition: ``service Foo { ... }``
_SERVICE_RX = re.compile(r"\bservice\s+(\w+)\s*\{")

# RPC definition: ``rpc MethodName(RequestType) returns (ResponseType)``
_RPC_RX = re.compile(r"\brpc\s+(\w+)\s*\(\s*(\w+)\s*\)\s*returns\s*\(\s*(\w+)\s*\)")

# Message definition: ``message MessageName { ... }``
_MESSAGE_RX = re.compile(r"\bmessage\s+(\w+)\s*\{")

# Import: ``import "path/to/file.proto"``
_IMPORT_RX = re.compile(r'\bimport\s+"([^"]+)"')

# Package: ``package name.v1;``
_PACKAGE_RX = re.compile(r"\bpackage\s+([\w.]+)\s*;")


def extract_proto(path: Path, *, content: str | bytes | None = None) -> dict:
    """Extract services, RPCs, messages, and imports from a .proto file.

    Returns a graph extraction dict with ``nodes`` and ``edges`` lists.
    """
    if content is not None:
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = content
    else:
        text = path.read_text(encoding="utf-8", errors="replace")

    str_path = str(path)
    stem = _file_stem(path)
    file_nid = _make_id(stem)

    nodes: list[dict] = []
    edges: list[dict] = []

    # Track which lines things are on for source_location
    lines = text.split("\n")

    # Extract package name
    pkg_match = _PACKAGE_RX.search(text)
    pkg_name = pkg_match.group(1) if pkg_match else None

    # Extract imports
    for m in _IMPORT_RX.finditer(text):
        import_path = m.group(1)
        line = text[: m.start()].count("\n") + 1
        import_nid = _make_id(import_path)
        nodes.append({
            "id": import_nid,
            "label": import_path,
            "file_type": "code",
            "source_file": str_path,
            "source_location": f"L{line}",
            "_origin": "proto_import",
        })
        edges.append({
            "source": file_nid,
            "target": import_nid,
            "relation": "imports_from",
            "confidence": "EXTRACTED",
            "source_file": str_path,
            "source_location": f"L{line}",
            "weight": 1.0,
        })

    # Extract services
    for m in _SERVICE_RX.finditer(text):
        svc_name = m.group(1)
        line = text[: m.start()].count("\n") + 1
        svc_nid = _make_id(stem, svc_name)
        # Fully-qualified service name
        fqn_svc = f"{pkg_name}.{svc_name}" if pkg_name else svc_name
        fqn_svc_nid = _make_id(fqn_svc)

        # Emit simple service node
        nodes.append({
            "id": svc_nid,
            "label": svc_name,
            "file_type": "code",
            "source_file": str_path,
            "source_location": f"L{line}",
            "_origin": "proto_service",
        })
        edges.append({
            "source": file_nid,
            "target": svc_nid,
            "relation": "contains",
            "confidence": "EXTRACTED",
            "source_file": str_path,
            "source_location": f"L{line}",
            "weight": 1.0,
        })

        # Find RPCs inside this service by scanning its body.
        # Find the matching closing brace.
        # Body starts right after the opening brace (included in the regex match).
        body_start = m.end()
        depth = 1
        pos = body_start
        while depth > 0 and pos < len(text):
            c = text[pos]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            pos += 1
        svc_body = text[body_start : pos - 1]  # Exclude closing brace
        svc_line_offset = text[:body_start].count("\n")

        for rm in _RPC_RX.finditer(svc_body):
            method_name = rm.group(1)
            req_type = rm.group(2)
            res_type = rm.group(3)
            rpc_line = svc_line_offset + svc_body[: rm.start()].count("\n") + 1

            rpc_nid = _make_id(stem, svc_name, method_name)

            nodes.append({
                "id": rpc_nid,
                "label": method_name,
                "file_type": "code",
                "source_file": str_path,
                "source_location": f"L{rpc_line}",
                "_origin": "proto_rpc",
            })
            # RPC is contained by the service
            edges.append({
                "source": svc_nid,
                "target": rpc_nid,
                "relation": "contains",
                "confidence": "EXTRACTED",
                "source_file": str_path,
                "source_location": f"L{rpc_line}",
                "weight": 1.0,
            })

            # Emit request/response type references
            for type_name, role in [(req_type, "request_type"), (res_type, "response_type")]:
                type_nid = _make_id(type_name)
                edges.append({
                    "source": rpc_nid,
                    "target": type_nid,
                    "relation": "references",
                    "context": role,
                    "confidence": "EXTRACTED",
                    "source_file": str_path,
                    "source_location": f"L{rpc_line}",
                    "weight": 1.0,
                })

    # Extract message types
    for m in _MESSAGE_RX.finditer(text):
        msg_name = m.group(1)
        line = text[: m.start()].count("\n") + 1
        msg_nid = _make_id(stem, msg_name)

        nodes.append({
            "id": msg_nid,
            "label": msg_name,
            "file_type": "code",
            "source_file": str_path,
            "source_location": f"L{line}",
            "_origin": "proto_message",
        })
        edges.append({
            "source": file_nid,
            "target": msg_nid,
            "relation": "contains",
            "confidence": "EXTRACTED",
            "source_file": str_path,
            "source_location": f"L{line}",
            "weight": 1.0,
        })

    return {"nodes": nodes, "edges": edges}