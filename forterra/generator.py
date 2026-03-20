"""
Generator — Writes generated Terraform files to disk.

HOW THIS WORKS:
- Takes the output from AIEngine (dict of filename → code)
- Creates the directory structure
- Writes each file
- Returns list of files written

This is a simple module — the heavy lifting is done by the AI engine.
"""

from pathlib import Path
from typing import Dict, List


class Generator:
    """Writes generated Terraform files to disk."""

    def write_files(self, output_dir: Path, files: Dict[str, str]) -> List[str]:
        """
        Write generated Terraform files to the output directory.

        Args:
            output_dir: Directory to write files to
            files: Dict mapping filename to content (e.g., {"main.tf": "resource ..."})

        Returns:
            List of relative file paths that were written
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        written = []

        for filename, content in files.items():
            # Handle nested paths (e.g., "modules/vpc/main.tf")
            filepath = output_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)

            # Write the file
            filepath.write_text(content)
            written.append(str(filepath.relative_to(output_dir.parent) if output_dir.parent != filepath.parent else filename))

        return sorted(written)
