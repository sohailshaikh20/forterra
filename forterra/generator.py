"""Writes generated Terraform files to disk."""

from pathlib import Path
from typing import Dict, List


class Generator:
    def write_files(self, output_dir: Path, files: Dict[str, str]) -> List[str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        written = []
        for filename, content in files.items():
            filepath = output_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content)
            written.append(filename)
        return sorted(written)
