# coding: utf-8
import os
from typing import Iterable
import logging

# wrapper for Process
def cached_proc_property(fn):
    @property
    def wrapped_call(self):
        if self.invalid:
            return None
        # it's ok to not check validity if querying cache
        if fn.__name__ in self.cache:
            return self.cache[fn.__name__]
        # check validity since here
        procdir = f'/proc/{self.pid}'
        if not (os.path.exists(procdir) and os.path.isdir(procdir)):
            self.invalid = True
            return ''
        procfile = f'/proc/{self.pid}/{fn.__name__}'
        if not (os.path.exists(procfile) and os.path.isfile(procfile)):
            self.cache[fn.__name__] = None
            return None
        retval = fn(self)
        self.cache[fn.__name__] = retval
        return retval

    return wrapped_call


def cached_kernel_property(fn):
    @property
    def wrapped_call(self):
        # it's ok to not check validity if querying cache
        if fn.__name__ in self.cache:
            return self.cache[fn.__name__]
        retval = fn(self)
        self.cache[fn.__name__] = retval
        return retval

    return wrapped_call


# wrapper
def noexcept(fn, fail_ret=0):
    def wrapped_call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            logging.debug(e)
            return fail_ret

    return wrapped_call


def pattern_search(buf: bytes, target: bytes, mask: Iterable, start: int = 0) -> int:
    if not mask:
        return buf.find(target, start)
    else:
        for i in range(start, len(buf)):
            mismatch = False
            for j, t in enumerate(target):
                if j in mask:
                    continue
                if buf[i + j] != t:
                    mismatch = True
                    break
            if not mismatch:
                return i
        return -1
