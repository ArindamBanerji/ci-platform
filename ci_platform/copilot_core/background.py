"""Shared background task management for non-decision-critical work.

BackgroundTaskManager is intended for Phase-4 work that does not affect the
current recommendation, gates, proof authority, or counters. Callers should not
use it for action selection, confidence, Decision/Outcome writes, DK/L5/Welford
updates, conservation gates, or any value required by the current response.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any, Awaitable, Coroutine, Deque, cast


async def _await_any(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


@dataclass(frozen=True)
class BackgroundTaskError:
    """Sanitized failure details for diagnostics."""

    name: str
    exception_type: str
    message: str


@dataclass(frozen=True)
class BackgroundTaskStatus:
    """Point-in-time task manager diagnostics."""

    submitted: int
    completed: int
    failed: int
    cancelled: int
    in_flight: int
    last_errors: tuple[BackgroundTaskError, ...]


class BackgroundTaskManager:
    """Retain and observe async tasks used for Phase-4 background work."""

    def __init__(
        self,
        *,
        max_errors: int = 10,
        logger: logging.Logger | None = None,
    ) -> None:
        if max_errors <= 0:
            raise ValueError("max_errors must be greater than zero")

        self._lock = threading.RLock()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._last_errors: Deque[BackgroundTaskError] = deque(maxlen=max_errors)
        self._submitted = 0
        self._completed = 0
        self._failed = 0
        self._cancelled = 0
        self._logger = logger or logging.getLogger(__name__)

    def submit(
        self,
        awaitable: Awaitable[Any],
        *,
        name: str | None = None,
    ) -> asyncio.Task[Any]:
        """Schedule an awaitable and retain it until completion.

        Exceptions are recorded in diagnostics and logged by the done callback.
        The task is returned so callers or tests may await it directly when
        needed.
        """

        if not inspect.isawaitable(awaitable):
            raise TypeError("submit() requires an awaitable")

        if inspect.iscoroutine(awaitable):
            coroutine = cast(Coroutine[Any, Any, Any], awaitable)
        else:
            coroutine = _await_any(awaitable)

        task: asyncio.Task[Any] = asyncio.create_task(coroutine, name=name)
        with self._lock:
            self._submitted += 1
            self._tasks.add(task)
        task.add_done_callback(self._on_done)
        return task

    async def drain(self, timeout: float | None = None) -> BackgroundTaskStatus:
        """Wait for currently submitted tasks to finish and return diagnostics."""

        with self._lock:
            tasks = tuple(self._tasks)

        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=timeout)
            if pending:
                pending_names = sorted(task.get_name() for task in pending)
                raise TimeoutError(
                    "background tasks did not finish before timeout: "
                    + ", ".join(pending_names)
                )

            for task in done:
                if not task.cancelled():
                    task.exception()

        return self.stats()

    async def shutdown(
        self,
        *,
        cancel: bool = True,
        timeout: float | None = None,
    ) -> BackgroundTaskStatus:
        """Drain or cancel in-flight tasks during application shutdown/tests."""

        if cancel:
            with self._lock:
                tasks = tuple(self._tasks)
            for task in tasks:
                task.cancel()

        return await self.drain(timeout=timeout)

    def stats(self) -> BackgroundTaskStatus:
        """Return structured diagnostics without task payloads or stack traces."""

        with self._lock:
            return BackgroundTaskStatus(
                submitted=self._submitted,
                completed=self._completed,
                failed=self._failed,
                cancelled=self._cancelled,
                in_flight=len(self._tasks),
                last_errors=tuple(self._last_errors),
            )

    def get_status(self) -> dict[str, Any]:
        """Return JSON-friendly diagnostics."""

        status = self.stats()
        return {
            "submitted": status.submitted,
            "completed": status.completed,
            "failed": status.failed,
            "cancelled": status.cancelled,
            "in_flight": status.in_flight,
            "last_errors": [
                {
                    "name": error.name,
                    "exception_type": error.exception_type,
                    "message": error.message,
                }
                for error in status.last_errors
            ],
        }

    def _on_done(self, task: asyncio.Task[Any]) -> None:
        with self._lock:
            self._tasks.discard(task)

        if task.cancelled():
            error = BackgroundTaskError(
                name=task.get_name(),
                exception_type="CancelledError",
                message="cancelled",
            )
            with self._lock:
                self._cancelled += 1
                self._failed += 1
                self._last_errors.append(error)
            self._logger.warning("background task cancelled: %s", task.get_name())
            return

        exc = task.exception()
        if exc is None:
            with self._lock:
                self._completed += 1
            return

        error = BackgroundTaskError(
            name=task.get_name(),
            exception_type=type(exc).__name__,
            message=self._sanitize_exception_message(exc),
        )
        with self._lock:
            self._failed += 1
            self._last_errors.append(error)
        self._logger.warning(
            "background task failed: %s (%s)",
            task.get_name(),
            type(exc).__name__,
        )

    @staticmethod
    def _sanitize_exception_message(exc: BaseException) -> str:
        message = str(exc)
        if not message:
            return ""
        message = message.replace("\r", " ").replace("\n", " ")
        if len(message) > 200:
            return message[:197] + "..."
        return message
