"""Copy the project's garak generator into the venv so garak can import it.

garak resolves --model_type as garak.generators.<module>.<Class> (see
_plugins.load_plugin), so a custom generator has to sit inside the installed
garak package. The source of truth stays in garak_plugins/ under version
control; this script installs it.

Run after creating or rebuilding the venv:
    python install_garak_plugin.py
"""

import shutil
import sys
from pathlib import Path

PLUGINS = ["ragsec.py"]


def main():
    project_dir = Path(__file__).resolve().parent
    source_dir = project_dir / "garak_plugins"

    try:
        import garak.generators
    except ImportError:
        print("garak is not installed in this interpreter.")
        print(f"Try: {sys.executable} -m pip install garak")
        return 1

    target_dir = Path(garak.generators.__file__).resolve().parent

    for filename in PLUGINS:
        source = source_dir / filename
        if not source.is_file():
            print(f"missing source plugin: {source}")
            return 1
        target = target_dir / filename
        shutil.copyfile(source, target)
        print(f"installed {filename} -> {target}")

    print("\nDone. Verify with:")
    print("  garak --list_generators | findstr ragsec")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
