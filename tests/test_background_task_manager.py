import asyncio
from pathlib import Path

import pytest

from ci_platform.copilot_core import BackgroundTaskManager


@pytest.mark.asyncio
async def test_background_task_retained_until_completion():
    manager = BackgroundTaskManager()
    release = asyncio.Event()

    async def work():
        await release.wait()
        return "done"

    task = manager.submit(work(), name="retained")

    assert manager.get_status()["submitted"] == 1
    assert manager.get_status()["in_flight"] == 1

    release.set()
    await manager.drain()

    assert await task == "done"
    assert manager.get_status()["completed"] == 1
    assert manager.get_status()["in_flight"] == 0


@pytest.mark.asyncio
async def test_successful_task_completion_updates_diagnostics():
    manager = BackgroundTaskManager()

    async def work():
        return 42

    task = manager.submit(work(), name="success")
    status = await manager.drain()

    assert await task == 42
    assert status.submitted == 1
    assert status.completed == 1
    assert status.failed == 0
    assert status.in_flight == 0
    assert status.last_errors == ()


@pytest.mark.asyncio
async def test_exception_capture_and_logging_without_swallowing_failure(caplog):
    manager = BackgroundTaskManager()

    async def work():
        raise RuntimeError("safe diagnostic failure")

    task = manager.submit(work(), name="failing")
    await manager.drain()

    assert task.done()
    assert isinstance(task.exception(), RuntimeError)
    status = manager.get_status()
    assert status["submitted"] == 1
    assert status["completed"] == 0
    assert status["failed"] == 1
    assert status["last_errors"] == [
        {
            "name": "failing",
            "exception_type": "RuntimeError",
            "message": "safe diagnostic failure",
        }
    ]
    assert "background task failed: failing (RuntimeError)" in caplog.text


@pytest.mark.asyncio
async def test_drain_raises_timeout_without_arbitrary_sleep():
    manager = BackgroundTaskManager()
    release = asyncio.Event()

    async def work():
        await release.wait()

    manager.submit(work(), name="pending")

    with pytest.raises(TimeoutError):
        await manager.drain(timeout=0)

    release.set()
    await manager.drain()
    assert manager.get_status()["completed"] == 1


@pytest.mark.asyncio
async def test_shutdown_can_cancel_in_flight_tasks():
    manager = BackgroundTaskManager()
    release = asyncio.Event()

    async def work():
        await release.wait()

    manager.submit(work(), name="cancel-me")
    status = await manager.shutdown(cancel=True)

    assert status.failed == 1
    assert status.cancelled == 1
    assert status.in_flight == 0
    assert status.last_errors[0].exception_type == "CancelledError"


@pytest.mark.asyncio
async def test_cross_copilot_generic_usage():
    manager = BackgroundTaskManager()
    completed = []

    async def work(domain):
        completed.append(domain)

    manager.submit(work("soc"), name="soc-telemetry")
    manager.submit(work("trading"), name="trading-telemetry")
    manager.submit(work("purchasing"), name="purchasing-telemetry")
    await manager.drain()

    assert completed == ["soc", "trading", "purchasing"]
    assert manager.get_status()["completed"] == 3


def test_invalid_max_errors_rejected():
    with pytest.raises(ValueError):
        BackgroundTaskManager(max_errors=0)


def test_submit_requires_awaitable():
    manager = BackgroundTaskManager()

    with pytest.raises(TypeError):
        manager.submit(object())  # type: ignore[arg-type]


def test_package_4_does_not_wire_soc_decision_route():
    repo_root = Path(__file__).resolve().parents[2]
    triage_path = (
        repo_root
        / "gen-ai-roi-demo-v4-v50"
        / "backend"
        / "app"
        / "routers"
        / "triage.py"
    )
    triage_source = triage_path.read_text(encoding="utf-8")

    assert "BackgroundTaskManager" not in triage_source
    assert "ci_platform.copilot_core.background" not in triage_source
