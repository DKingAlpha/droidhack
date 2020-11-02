from ._utils import *
from ctypes import *
from .procfs import Process, Flags

'''
    you are lucky if your system ship with /dev/mem and /dev/kmem
'''


class MemoryFile:
    def __init__(self, filepath, node_type):
        self.invalid = False
        if not os.path.exists(filepath):
            self.invalid = True
            return
        self.x64 = Process(1).x64  # init
        self.cache = {}
        self._libc = cdll.LoadLibrary("libc.so")
        self.file = open(filepath, 'rb')
        self.read = noexcept(self.file.read)
        self.write = noexcept(self.file.write)

    def __del__(self):
        if self.file:
            self.file.close()

    @noexcept
    def seek(self, pos, whence=0):
        if self.x64:
            self._libc.lseek64.restype = c_uint64
            return self._libc.lseek64(self.file.fileno(), c_int64(pos), whence)
        else:
            self._libc.lseek.restype = c_uint32
            return self._libc.lseek(self.file.fileno(), c_int32(pos), whence)

    @noexcept
    def tell(self):
        if self.x64:
            self._libc.lseek64.restype = c_uint64
            return self._libc.lseek64(self.file.fileno(), 0, 1)
        else:
            self._libc.lseek.restype = c_uint32
            return self._libc.lseek(self.file.fileno(), 0, 1)


class DevMem(MemoryFile):
    def __init__(self):
        super().__init__("/dev/mem", 1)


class DevKmem(MemoryFile):
    def __init__(self):
        super().__init__("/dev/kmem", 2)
        self.ksym_on()

    @staticmethod
    def ksym_on():
        Flags.set('kernel/kptr_restrict', 0)

    @staticmethod
    def ksym_off():
        Flags.set('kernel/kptr_restrict', 2)

    @cached_property
    def ksym(self):
        fp = '/proc/kallsyms'
        if not os.path.exists(fp):
            return {}
        retval = {}
        f = open(fp, 'r')
        for i in f.readlines():
            raw = i.strip().split()
            if len(raw) == 3:
                if raw[2] not in retval:
                    retval[raw[2]] = []
                info = retval[raw[2]]
                info.append({'type': raw[1], 'addr': int(raw[0], 16)})
        f.close()
        return retval

    def get_sym(self, symbol) -> list:
        return self.ksym.get(symbol, [])
