from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_mypy_config_exists() -> None:
    pyproject = ROOT / "pyproject.toml"
    mypy_ini = ROOT / "mypy.ini"

    has_pyproject_config = (
        pyproject.exists()
        and "[tool.mypy]" in pyproject.read_text(encoding="utf-8")
    )
    has_ini_config = (
        mypy_ini.exists()
        and "[mypy]" in mypy_ini.read_text(encoding="utf-8")
    )

    assert has_pyproject_config or has_ini_config


def test_mypy_passes_with_config() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "ci_platform/",
            "--ignore-missing-imports",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

    output = "\n".join(
        (result.stdout + "\n" + result.stderr).splitlines()[-40:]
    )
    assert result.returncode == 0, output


def test_unsuppressed_mypy_targets_pass_individually() -> None:
    targets = [
        "ci_platform/auth",
        "ci_platform/connectors",
        "ci_platform/graph",
    ]

    for target in targets:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                target,
                "--ignore-missing-imports",
                "--no-incremental",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = "\n".join(
            (result.stdout + "\n" + result.stderr).splitlines()[-40:]
        )
        assert result.returncode == 0, f"{target}\n{output}"
