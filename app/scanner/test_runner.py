"""Bounded concurrent test runner executing security test cases against a target."""

import asyncio
import inspect
from typing import Any, Callable, List, Optional

import httpx

from app.ml.dataset import TestCaseRecord
from app.scanner.base import ExecutionResult
from app.scanner.target_client import TargetClient


class TestRunner:
    """Orchestrates bounded concurrent execution of test cases against an authorized target."""

    def __init__(
        self,
        target_url: str,
        timeout_seconds: float = 10.0,
        max_concurrency: int = 5,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.target_url = target_url
        self.timeout_seconds = timeout_seconds
        self.max_concurrency = max(1, min(max_concurrency, 10))
        self.http_client = http_client

    async def run_tests(
        self,
        test_cases: List[TestCaseRecord],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        on_test_start: Optional[Callable[[TestCaseRecord], Any]] = None,
        on_test_complete: Optional[Callable[[TestCaseRecord, ExecutionResult], Any]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[ExecutionResult]:
        """Execute test cases with bounded concurrency, lifecycle callbacks, and cancellation awareness."""
        semaphore = asyncio.Semaphore(self.max_concurrency)
        results: List[ExecutionResult] = []
        completed_count = 0
        total_count = len(test_cases)

        client = self.http_client or httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
        )
        should_close = self.http_client is None

        async def _run_single(tc: TestCaseRecord) -> Optional[ExecutionResult]:
            nonlocal completed_count
            if is_cancelled and is_cancelled():
                return None

            async with semaphore:
                if is_cancelled and is_cancelled():
                    return None

                if on_test_start:
                    try:
                        if inspect.iscoroutinefunction(on_test_start):
                            await on_test_start(tc)
                        else:
                            on_test_start(tc)
                    except Exception:
                        pass

                res = await TargetClient.execute_test(
                    target_url=self.target_url,
                    test_case_id=tc.id,
                    category=tc.category,
                    input_text=tc.input,
                    timeout_seconds=self.timeout_seconds,
                    client=client,
                    metadata=tc.metadata,
                )

                completed_count += 1
                if progress_callback:
                    try:
                        progress_callback(completed_count, total_count)
                    except Exception:
                        pass

                if on_test_complete:
                    try:
                        if inspect.iscoroutinefunction(on_test_complete):
                            await on_test_complete(tc, res)
                        else:
                            on_test_complete(tc, res)
                    except Exception:
                        pass

                return res

        try:
            tasks = [_run_single(tc) for tc in test_cases]
            raw_results = await asyncio.gather(*tasks)
            # Filter out any cancelled items
            return [r for r in raw_results if r is not None]
        finally:
            if should_close:
                await client.aclose()
