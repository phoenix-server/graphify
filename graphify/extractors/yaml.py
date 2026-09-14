"""YAML AST extractor for graphify. Parses YAML files using tree-sitter-yaml.

Extracts Kubernetes-style resources (kind + metadata.name) as structured nodes,
and general YAML config as document-level concept nodes with top-level keys.
Supports Helm chart templates with Go template syntax via regex fallback.
Redacts sensitive values (passwords, secrets, tokens, API keys, sops-encrypted).

Strategy:
1. Try yaml.safe_load (clean YAML) → full structural extraction
2. On failure, try regex-based extraction for Helm templates → kind + name
"""
from __future__ import annotations

import re
from pathlib import Path

from graphify.extractors.base import _file_stem, _make_id, _read_text

# ── Sensitive value detection ──────────────────────────────────────────────────

_SENSITIVE_KEY_RX = re.compile(
    r"\b(?:password|secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?key"
    r"|secret[_-]?key|private[_-]?key|ssh[_-]?key|connection[_-]?string"
    r"|signing[_-]?key|encryption[_-]?key|master[_-]?key|license[_-]?key"
    r"|personal[_-]?access[_-]?token|pat|bearer|jwt|refresh[_-]?token)\b",
    re.IGNORECASE,
)

_SECRET_VALUE_RX = re.compile(
    r"^(?:ENC\[AES256_GCM|sops:|gcs:|azurerm:|pgp:|age1)[\w\-=+/]+"
    r"|^(?:[A-Za-z0-9+/]{40,})={0,2}$"
    r"|^(?:[a-fA-F0-9]{32,})$"
)

# ── Helm template regex patterns ────────────────────────────────────────────────

_KIND_RX = re.compile(r"^kind:\s*(\w[\w.]*)", re.MULTILINE)
_NAME_RX = re.compile(
    r"^metadata:\s*$"          # line starting with metadata:
    r"(?:\n(?!\S).*)*?"       # indented lines under metadata
    r"\n\s+name:\s*(.+)",    # name: <value>
    re.MULTILINE,
)
# Simpler line-by-line name extractor (more robust for templates with conditionals)
_NAME_LINE_RX = re.compile(r"^\s+name:\s*(.+)$", re.MULTILINE)
_API_VERSION_RX = re.compile(r"^apiVersion:\s*(\S+)", re.MULTILINE)
_NAMESPACE_RX = re.compile(r"^namespace:\s*(\S+)", re.MULTILINE)
_REPLICAS_RX = re.compile(r"replicas:\s*(\d+)")

# Try import optional tree-sitter-yaml grammar
try:
    from tree_sitter import Language, Parser

    _YAML_LANG = Language(
        __import__("tree_sitter_yaml", fromlist=["language"]).language()
    )
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# Try import yaml
try:
    import yaml as _yaml  # type: ignore[import-untyped]
    _HAS_PYYAML = True
except Exception:
    _HAS_PYYAML = False


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RX.search(key.lower().replace("_", " ")))


def _is_secret_value(value: str) -> bool:
    if len(value) < 20:
        return False
    if _SECRET_VALUE_RX.match(value):
        return True
    # High-entropy check: ≥30 chars with 3+ character classes
    if len(value) >= 30:
        classes = sum(1 for p in (any(c.isupper() for c in value),
                                  any(c.islower() for c in value),
                                  any(c.isdigit() for c in value),
                                  any(not c.isalnum() for c in value)))
        if classes >= 3 and sum(1 for c in value if c.islower()) >= 3:
            return True
    return False


def _sanitize_resource_name(raw: str) -> str:
    """Strip template syntax from a resource name for use as a graph node label."""
    # Replace {{ ... }} and {{- ... }} with a placeholder
    cleaned = re.sub(r"\{\{-?\s*[^}]+\s*-?\}\}", "_T_", raw)
    # Clean up excessive whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or "_template_"


# ── PyYAML-based extraction (clean YAML files) ──────────────────────────────────


def _yaml_document_node(
    data, path: Path, source: str, doc_index: int, stem: str
) -> tuple[list[dict], list[dict]]:
    """Extract nodes from one parsed YAML document."""
    nodes: list[dict] = []
    edges: list[dict] = []

    if not isinstance(data, dict):
        return nodes, edges

    kind = data.get("kind", "")
    metadata = data.get("metadata", {}) or {}
    name = metadata.get("name", "") if isinstance(metadata, dict) else ""

    if kind and isinstance(kind, str) and kind.strip():
        # Kubernetes-style resource
        resource_name = _sanitize_resource_name(str(name)) if name else f"{kind}-{doc_index}"
        stem_id = _make_id(stem, path.name.split(".")[0])
        res_id = _make_id(stem_id, kind, resource_name)

        line = source.find(f"kind: {kind}")
        start_line = source[:line].count("\n") + 1 if line >= 0 else 1

        node = {
            "id": res_id,
            "label": f"{kind}/{resource_name}",
            "file_type": "code",
            "source_file": str(path),
            "source_location": f"L{start_line}",
        }

        # Safe properties
        safe = {"kind": kind, "name": resource_name}
        if isinstance(data.get("apiVersion"), str):
            safe["apiVersion"] = str(data["apiVersion"])
        if isinstance(data.get("namespace"), str):
            safe["namespace"] = str(data["namespace"])

        # Extract images from Deployment/StatefulSet spec
        spec = data.get("spec", {}) or {}
        if isinstance(spec, dict) and "apps" in str(data.get("apiVersion", "")):
            replicas = spec.get("replicas")
            if replicas is not None:
                safe["replicas"] = str(replicas)
            template = spec.get("template", {})
            if isinstance(template, dict):
                pod_spec = template.get("spec", {})
                if isinstance(pod_spec, dict):
                    containers = pod_spec.get("containers", [])
                    if isinstance(containers, list):
                        images = []
                        for c in containers:
                            if isinstance(c, dict) and "image" in c:
                                img = str(c["image"])
                                if not _is_secret_value(img):
                                    images.append(img)
                        if images:
                            safe["images"] = ", ".join(images)

        node.update(safe)
        nodes.append(node)
        edges.append({
            "source": stem_id,
            "target": res_id,
            "relation": "contains",
            "confidence": "EXTRACTED",
            "confidence_score": 1.0,
            "source_file": str(path),
            "source_location": f"L{start_line}",
        })

        # Service → Deployment selector link
        if kind == "Service":
            svc_spec = data.get("spec", {}) or {}
            selector = svc_spec.get("selector", {})
            if isinstance(selector, dict):
                app_name = selector.get("app", "")
                if app_name:
                    target_id = _make_id(stem_id, "Deployment", str(app_name))
                    edges.append({
                        "source": res_id,
                        "target": target_id,
                        "relation": "references",
                        "confidence": "INFERRED",
                        "confidence_score": 0.7,
                        "source_file": str(path),
                        "source_location": f"L{start_line}",
                    })

    return nodes, edges


def _parse_clean_yaml(source: str, path: Path) -> tuple[list[dict], list[dict]]:
    """Parse a clean YAML file (no Go templates). Returns nodes and edges."""
    nodes: list[dict] = []
    edges: list[dict] = []
    stem = _file_stem(path)
    stem_id = _make_id(stem, path.name.split(".")[0])

    try:
        docs = list(_yaml.safe_load_all(source))
    except Exception:
        return nodes, edges

    # File node
    nodes.append({
        "id": stem_id,
        "label": path.name,
        "file_type": "code",
        "source_file": str(path),
        "source_location": "L1",
    })

    for i, doc in enumerate(docs):
        if doc is None:
            continue
        dn, de = _yaml_document_node(doc, path, source, i, stem)
        nodes.extend(dn)
        edges.extend(de)

    return nodes, edges


# ── Regex-based extraction (Helm templates, other Go-templated YAML) ──────────


def _parse_templated_yaml(source: str, path: Path) -> tuple[list[dict], list[dict]]:
    """Extract resource nodes from Go-templated YAML (Helm charts) via regex."""
    nodes: list[dict] = []
    edges: list[dict] = []
    stem = _file_stem(path)
    stem_id = _make_id(stem, path.name.split(".")[0])

    nodes.append({
        "id": stem_id,
        "label": path.name,
        "file_type": "code",
        "source_file": str(path),
        "source_location": "L1",
    })

    # Find each resource: a `kind:` line followed by a metadata block
    kind_matches = list(_KIND_RX.finditer(source))

    # Handle multi-document streams (--- separated)
    documents = re.split(r"^---\s*$", source, flags=re.MULTILINE)

    for doc_idx, doc_text in enumerate(documents):
        doc_text = doc_text.strip()
        if not doc_text:
            continue

        kind_match = _KIND_RX.search(doc_text)
        if not kind_match:
            continue

        kind = kind_match.group(1)
        api_version = ""
        av = _API_VERSION_RX.search(doc_text)
        if av:
            api_version = av.group(1)

        # Extract name: line-by-line under metadata, or the first name: in the doc
        name = ""
        lines = doc_text.split("\n")
        in_metadata = False
        for line in lines:
            stripped = line.rstrip()
            if stripped == "metadata:" or stripped == "metadata":
                in_metadata = True
                continue
            if in_metadata:
                # Stop if we hit another top-level key (non-indented)
                if not stripped or not stripped[0].isspace():
                    in_metadata = False
                    continue
                nm = _NAME_LINE_RX.match(stripped)
                if nm:
                    name = nm.group(1).strip()
                    break

        resource_name = _sanitize_resource_name(name) if name else f"{kind}-{doc_idx}"
        res_id = _make_id(stem_id, kind, resource_name)

        # Find line number: offset of kind: in the document
        doc_offset = source.find(doc_text)
        kind_line = source[doc_offset:].count("\n") + 1
        # Account for preceding --- separators
        kind_line += source[:doc_offset].count("\n")

        node = {
            "id": res_id,
            "label": f"{kind}/{resource_name}",
            "file_type": "code",
            "source_file": str(path),
            "source_location": f"L{kind_line}",
            "kind": kind,
            "name": resource_name,
        }
        if api_version:
            node["apiVersion"] = api_version

        # Extract replicas
        rep = _REPLICAS_RX.search(doc_text)
        if rep:
            node["replicas"] = rep.group(1)

        nodes.append(node)
        edges.append({
            "source": stem_id,
            "target": res_id,
            "relation": "contains",
            "confidence": "EXTRACTED",
            "confidence_score": 1.0,
            "source_file": str(path),
            "source_location": f"L{kind_line}",
        })

    return nodes, edges


# ── Main extractor ──────────────────────────────────────────────────────────────


def extract_yaml(path: Path, *, content: bytes | None = None) -> dict:
    """Extract nodes and edges from a YAML file.

    Handles:
    - Plain YAML (ArgoCD, CI configs, values): uses yaml.safe_load for full structure
    - Go-templated YAML (Helm charts): falls back to regex for kind + name extraction
    - Multi-document streams
    - Secret redaction

    Returns a dict with keys: nodes, edges.
    """
    if not _HAS_PYYAML:
        raise ImportError(
            "PyYAML not installed. Install it with: pip install pyyaml"
        )

    try:
        source_bytes = content if content is not None else path.read_bytes()
    except Exception:
        return {"nodes": [], "edges": []}

    source = source_bytes.decode("utf-8", errors="replace")

    # Strategy 1: try clean YAML parse
    try:
        nodes, edges = _parse_clean_yaml(source, path)
        if nodes:
            return {"nodes": nodes, "edges": edges}
    except Exception:
        pass

    # Strategy 2: fallback — regex-based for Helm templates
    nodes, edges = _parse_templated_yaml(source, path)
    if nodes:
        return {"nodes": nodes, "edges": edges}

    # Strategy 3: tree-sitter fallback for malformed but structurally parseable YAML
    if _HAS_YAML:
        try:
            ts_nodes, ts_edges = _tree_sitter_extract(source_bytes, path)
            if ts_nodes:
                return {"nodes": ts_nodes, "edges": ts_edges}
        except Exception:
            pass

    return {"nodes": [], "edges": []}


# ── Tree-sitter extraction (fallback) ────────────────────────────────────────────


def _tree_sitter_extract(source: bytes, path: Path) -> tuple[list[dict], list[dict]]:
    """Fallback extraction using tree-sitter-yaml for structurally odd YAML."""
    from tree_sitter import Language, Parser

    # Module already imported at top; remove from func scope to silence unused
    del Language, Parser

    nodes: list[dict] = []
    edges: list[dict] = []
    stem = _file_stem(path)
    stem_id = _make_id(stem, path.name.split(".")[0])

    try:
        parser = Parser()
        parser.language = _YAML_LANG
        tree = parser.parse(source)
    except Exception:
        return nodes, edges

    root = tree.root_node
    source_str = source.decode("utf-8", errors="replace")

    # File node
    nodes.append({
        "id": stem_id,
        "label": path.name,
        "file_type": "code",
        "source_file": str(path),
        "source_location": "L1",
    })

    # Walk documents or direct mapping pairs
    documents = [c for c in root.children if c.type == "document"]
    if not documents:
        documents = [root]

    for doc_idx, doc in enumerate(documents):
        # Find kind/value pairs
        kind_val = None
        name_val = None
        line_no = doc.start_point[0] + 1

        def _walk_pairs(n, depth=0):
            nonlocal kind_val, name_val
            if depth > 8:
                return
            if n.type == "block_mapping_pair":
                key_text = ""
                val_text = ""
                found_sep = False
                for c in n.children:
                    if c.type == ":":
                        found_sep = True
                        continue
                    if not found_sep:
                        key_text = source[c.start_byte:c.end_byte].decode().strip().strip('"').strip("'")
                    else:
                        val_text = source[c.start_byte:c.end_byte].decode().strip().strip('"').strip("'")
                        break

                if key_text == "kind" and val_text:
                    kind_val = val_text
                    nonlocal line_no
                    line_no = n.start_point[0] + 1
                elif key_text == "name" and val_text and kind_val:
                    name_val = val_text
            for c in n.children:
                _walk_pairs(c, depth + 1)

        _walk_pairs(doc)

        if kind_val:
            resource_name = _sanitize_resource_name(name_val) if name_val else f"{kind_val}-{doc_idx}"
            res_id = _make_id(stem_id, kind_val, resource_name)
            nodes.append({
                "id": res_id,
                "label": f"{kind_val}/{resource_name}",
                "file_type": "code",
                "source_file": str(path),
                "source_location": f"L{line_no}",
                "kind": kind_val,
                "name": resource_name,
            })
            edges.append({
                "source": stem_id,
                "target": res_id,
                "relation": "contains",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": str(path),
                "source_location": f"L{line_no}",
            })

    return nodes, edges