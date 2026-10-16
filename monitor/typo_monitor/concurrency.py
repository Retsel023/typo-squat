"""Rolling thread work with bounded submissions and cooperative cancellation."""

from concurrent.futures import CancelledError, FIRST_COMPLETED, ThreadPoolExecutor, wait
import threading


def bounded_map(function, items, *, workers, check_cancel=None, thread_name_prefix="worker"):
    """Yield ``(item, result)`` as work completes, keeping at most workers live.

    Running calls must have their own bounded deadlines/cancellation checks.
    On failure or cancellation, queued calls are cancelled and active calls are
    drained before returning. A worker-side guard prevents abandoned submissions
    from invoking the function while the coordinator handles the first error.
    """
    if not isinstance(workers, int) or isinstance(workers, bool) or workers < 1:
        raise ValueError("Worker count must be a positive integer.")
    stopped = threading.Event()
    failures, failure_lock = [], threading.Lock()
    pending = {}
    iterator = iter(items)
    exhausted = False

    def check():
        if check_cancel is not None:
            check_cancel()
        with failure_lock:
            if failures:
                raise failures[0]

    def invoke(item):
        if stopped.is_set():
            raise CancelledError()
        if check_cancel is not None:
            check_cancel()
        try:
            return function(item)
        except BaseException as error:
            with failure_lock:
                if not failures:
                    failures.append(error)
            stopped.set()
            raise

    check()
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix=thread_name_prefix)
    try:
        while True:
            check()
            while not exhausted and len(pending) < workers:
                check()
                try:
                    item = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                pending[executor.submit(invoke, item)] = item
            if not pending:
                return
            done, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
            check()
            for future in done:
                item = pending.pop(future)
                result = future.result()
                check()
                yield item, result
    finally:
        stopped.set()
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
