"""Install the built Hermes wheel in an empty virtual environment and discover its entry point."""

from __future__ import annotations

import importlib.metadata
import pathlib
import shutil
import subprocess
import sys
import tempfile
import venv


ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "plugins" / "aurels-hermes"


def run(*args: str) -> None:
    subprocess.run(args, check=True, cwd=ROOT)


with tempfile.TemporaryDirectory(prefix="aurels-hermes-e2e-") as temporary:
    work = pathlib.Path(temporary)
    wheels = work / "wheels"
    wheels.mkdir()
    run(sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheels), str(PACKAGE))
    wheel = next(wheels.glob("aurels_hermes-*.whl"))

    environment = work / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    run(str(python), "-m", "pip", "install", "--no-index", str(wheel))
    code = (
        "import importlib.metadata as m; "
        "entry=next(e for e in m.entry_points(group='hermes_agent.plugins') if e.name == 'aurels-hermes'); "
        "assert entry.value == 'aurels_hermes', entry.value; "
        "assert callable(getattr(entry.load(), 'register', None))"
    )
    run(str(python), "-c", code)

print("Hermes wheel installs and exposes the Hermes plugin entry point.")
