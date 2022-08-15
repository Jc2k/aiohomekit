"""
Debounce helper.
https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/helpers/debounce.py
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from logging import Logger
from typing import Generic, TypeVar

from .utils import async_create_task

_R_co = TypeVar("_R_co", covariant=True)


class Debouncer(Generic[_R_co]):
    """Class to rate limit calls to a specific command."""

    def __init__(
        self,
        logger: Logger,
        *,
        cooldown: float,
        immediate: bool,
        function: Callable[[], _R_co] | None = None,
    ) -> None:
        """Initialize debounce.

        immediate: indicate if the function needs to be called right away and
                   wait <cooldown> until executing next invocation.
        function: optional and can be instantiated later.
        """
        self.logger = logger
        self._function = function
        self.cooldown = cooldown
        self.immediate = immediate
        self._timer_task: asyncio.TimerHandle | None = None
        self._execute_at_end_of_timer: bool = False
        self._execute_lock = asyncio.Lock()

    @property
    def function(self) -> Callable[[], _R_co] | None:
        """Return the function being wrapped by the Debouncer."""
        return self._function

    @function.setter
    def function(self, function: Callable[[], _R_co]) -> None:
        """Update the function being wrapped by the Debouncer."""
        self._function = function

    def async_trigger(self) -> None:
        if self._timer_task:
            if not self._execute_at_end_of_timer:
                self._execute_at_end_of_timer = True

            return

        if not self.immediate:
            self._execute_at_end_of_timer = True
            self._schedule_timer()
            return

        async_create_task(self.async_call)

    async def async_call(self) -> None:
        """Call the function."""
        if self._timer_task:
            if not self._execute_at_end_of_timer:
                self._execute_at_end_of_timer = True

            return

        # Locked means a call is in progress. Any call is good, so abort.
        if self._execute_lock.locked():
            return

        if not self.immediate:
            self._execute_at_end_of_timer = True
            self._schedule_timer()
            return

        async with self._execute_lock:
            # Abort if timer got set while we're waiting for the lock.
            if self._timer_task:
                return

            task = asyncio.create_task(self._function())
            if task:
                await task

            self._schedule_timer()

    async def _handle_timer_finish(self) -> None:
        """Handle a finished timer."""
        self._timer_task = None

        if not self._execute_at_end_of_timer:
            return

        self._execute_at_end_of_timer = False

        # Locked means a call is in progress. Any call is good, so abort.
        if self._execute_lock.locked():
            return

        async with self._execute_lock:
            # Abort if timer got set while we're waiting for the lock.
            if self._timer_task:
                return  # type: ignore[unreachable]

            try:
                task = asyncio.create_task(self._function())
                if task:
                    await task
            except Exception:  # pylint: disable=broad-except
                self.logger.exception("Unexpected exception from %s", self.function)

            self._schedule_timer()

    def async_cancel(self) -> None:
        """Cancel any scheduled call."""
        if self._timer_task:
            self._timer_task.cancel()
            self._timer_task = None

        self._execute_at_end_of_timer = False

    def _schedule_timer(self) -> None:
        """Schedule a timer."""
        loop = asyncio.get_event_loop()
        self._timer_task = loop.call_later(
            self.cooldown,
            lambda: async_create_task(self._handle_timer_finish()),
        )
