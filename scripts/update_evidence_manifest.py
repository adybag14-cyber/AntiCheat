"""Deterministically update tracked evidence hashes and private authority hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
ROOT = SCRIPT_DIRECTORY.parent
DEFAULT_MANIFEST = ROOT / "evidence" / "manifest.json"

NEW_TRACKED_ARTIFACTS = (
    ".github/workflows/validate.yml",
    "README.md",
    "docs/09-randgrid-full-function-map.md",
    "docs/10-randgrid-source-reconstruction.md",
    "evidence/README.md",
    "evidence/randgrid-full-map.json",
    "evidence/randgrid-full-map.md",
    "evidence/randgrid-source-reconstruction-summary.json",
    "examples/randgrid-source-reconstruction.c",
    "scripts/ghidra/GhidraFullFunctionCatalog.java",
    "scripts/randgrid_full_map.py",
    "scripts/randgrid_source_reconstruction.py",
    "scripts/update_evidence_manifest.py",
    "tests/test_randgrid_full_map.py",
    "tests/test_randgrid_source_reconstruction.py",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(16 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def file_record(path: Path, *, public_path: str) -> dict[str, Any]:
    return {
        "path": public_path,
        "size": path.stat().st_size,
        "sha256": sha256(path),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--ghidra-catalog", type=Path, required=True)
    parser.add_argument("--instruction-dump", type=Path, required=True)
    parser.add_argument("--gap-dump", type=Path, required=True)
    parser.add_argument("--full-reconstruction", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    artifacts = dict(manifest.get("artifacts") or {})
    for relative in sorted(set(artifacts) | set(NEW_TRACKED_ARTIFACTS)):
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit(f"tracked manifest artifact is missing: {relative}")
        artifacts[relative] = sha256(path)

    ghidra_items = [
        json.loads(line)
        for line in args.ghidra_catalog.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not ghidra_items or ghidra_items[0].get("type") != "header":
        raise SystemExit("Ghidra catalog header is missing")
    if ghidra_items[-1].get("type") != "footer" or ghidra_items[-1].get("cancelled"):
        raise SystemExit("Ghidra catalog footer is missing or cancelled")
    header = ghidra_items[0]
    footer = ghidra_items[-1]

    manifest["schema_version"] = 2
    manifest["toolchain"].update(
        {
            "ghidra": header.get("ghidra_version"),
            "ghidra_language": header.get("language_id"),
            "ghidra_compiler_spec": header.get("compiler_spec_id"),
        }
    )
    manifest["authority_inputs"] = {
        "ghidra_catalog": {
            **file_record(
                args.ghidra_catalog,
                public_path="analysis/randgrid-full-map/ghidra-functions-v2.jsonl",
            ),
            "program": header.get("program"),
            "program_sha256": header.get("program_sha256"),
            "image_base": header.get("image_base"),
            "manager_function_count": header.get("ghidra_function_count"),
            "written_functions": footer.get("written_functions"),
            "cancelled": footer.get("cancelled"),
        },
        "instruction_dump": file_record(
            args.instruction_dump,
            public_path="analysis/randgrid-full-map-v2/instructions.tsv.gz",
        ),
        "gap_dump": file_record(
            args.gap_dump,
            public_path="analysis/randgrid-full-map-v2/gaps.tsv.gz",
        ),
        "full_source_like_reconstruction": file_record(
            args.full_reconstruction,
            public_path=(
                "analysis/randgrid-source-reconstruction/"
                "randgrid-source-like-reconstruction.c.gz"
            ),
        ),
    }
    manifest["artifacts"] = dict(sorted(artifacts.items()))
    rendered = json.dumps(manifest, indent=2) + "\n"
    temporary = args.manifest.with_suffix(args.manifest.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    os.replace(temporary, args.manifest)
    print(f"updated {args.manifest}")
    print(f"tracked artifacts: {len(artifacts)}")


if __name__ == "__main__":
    main()
