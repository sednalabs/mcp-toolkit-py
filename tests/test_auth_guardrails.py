import ast
import os


def _list_py_files(root: str) -> list[str]:
    paths: list[str] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [entry for entry in dirs if entry not in {"__pycache__", ".venv", "dist"}]
        for name in files:
            if name.endswith(".py"):
                paths.append(os.path.join(base, name))
    return paths


def _scan_forbidden_attributes(paths: list[str]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source, filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"claims", "token_claims"}:
                findings.append(f"{path}:{node.lineno}:{node.col_offset + 1} uses .{node.attr}")
    return findings


def test_auth_guardrails() -> None:
    root = os.path.join(os.path.dirname(__file__), "..", "src", "mcp_toolkit")
    files = _list_py_files(root)
    findings = _scan_forbidden_attributes(files)
    assert findings == []
