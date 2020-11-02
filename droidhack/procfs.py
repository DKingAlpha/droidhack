from __future__ import annotations

import re
import struct
from ctypes import *
from typing import Union as TUnion, Callable
from pathlib import Path

from ._utils import *

__all__ = ['Processes', 'Process', 'Memory', 'Flags', 'MapInfo']


class Processes:
    procs = ()

    def update(self):
        procs = []
        for d in os.listdir('/proc'):
            if d.isnumeric():
                pid = int(d)
                procs.append(Process(pid))
        self.procs = tuple(procs)

    def __iter__(self):
        for i in self.procs:
            yield i

    def __init__(self):
        self.update()

    def get(self, pid_or_cmd: TUnion[int, tuple, list, str], all=False):
        if isinstance(pid_or_cmd, int):
            for i in self.procs:
                if i.pid == pid_or_cmd:
                    return i
        elif isinstance(pid_or_cmd, (tuple, list)):
            retval = []
            for i in self.procs:
                if tuple(pid_or_cmd) == tuple(i.cmdline):
                    if not all:
                        return i
                    retval.append(i)
            return tuple(retval)
        elif isinstance(pid_or_cmd, str):
            retval = []
            for i in self.procs:
                if re.fullmatch(pid_or_cmd, ' '.join(i.cmdline)):
                    if not all:
                        return i
                    retval.append(i)
            return tuple(retval)
        else:
            raise Exception("unknown pid or cmdline")

    def find(self, cmdline: str) -> list:
        retval = []
        for i in self.procs:
            if cmdline in (' '.join(i.cmdline)):
                retval.append(i)
        return retval


class MapInfo(dict):
    """
    members:
        addr, size, perm, path, offset, dev, inode

    usage:
        m.addr or m['addr']
    """
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __repr__(self):
        return f"addr: {self.addr:x}, size: {self.size:x}, offset: {self.offset:08x} {self.perm} {self.path}"


class Process:
    def __init__(self, pid):
        self.pid = pid
        self.maps_config = {
            'maxsplit': 5,
            'index': {'addr': 0, 'perm': 1, 'offset': 2, 'dev': 3, 'inode': 4, 'path': 5}
        }
        self.cache = {}
        self.invalid = False

    def __repr__(self):
        return f'[{self.pid}]{"".join(self.cmdline)}'

    def update(self):
        self.cache = {}

    @cached_property
    def x64(self) -> bool:
        tmp = open(f'/proc/{self.pid}/maps', 'r')
        addrs = tmp.readline().rstrip().split()[self.maps_config['index']['addr']].split('-')
        tmp.close()
        return len(addrs[0]) > 8

    @property
    def x32(self) -> bool:
        return not self.x64

    def find(self, path: str) -> list:
        retval = []
        for i in self.maps:
            if path in i.path:
                retval.append(i)
        return retval

    @cached_proc_property
    def cmdline(self) -> tuple:
        cmdline_content = Path(f'/proc/{self.pid}/cmdline').read_text()
        if not cmdline_content:
            return ()
        cmdlines = cmdline_content.split('\x00')
        return tuple([c for c in cmdlines if c != ''])

    @cached_proc_property
    def maps(self) -> list:
        maps_content = Path(f'/proc/{self.pid}/maps').read_text()
        if not maps_content:
            return []
        retval = []
        for m in maps_content.splitlines():
            minfo = m.rstrip().split(maxsplit=self.maps_config['maxsplit'])
            mm = MapInfo()
            for col in self.maps_config['index']:
                col_index = self.maps_config['index'][col]
                if col_index < len(minfo):
                    mm[col] = minfo[col_index]
                else:
                    mm[col] = ''
            # parse addr
            maddr = str(mm.addr).split('-')
            if len(maddr) == 2:
                mm.addr = int(maddr[0], 16)
                mm.size = int(maddr[1], 16) - int(maddr[0], 16)
            # parse offset
            offset = int(mm.offset, 16)
            mm.offset = offset
            # parse inode
            inode = int(mm.inode, 10)
            mm.inode = inode
            retval.append(mm)

        return retval

    @cached_proc_property
    def mem(self) -> Memory:
        return Memory(self.pid, self.x64)

    def search(self, pattern: str, addr: int = 0, size: int = 0, pattern_type: str = '', limit: int = 1,
               verbose: bool = False, onfound: Callable = None) -> list:
        """
        See Memory.search
        """
        if limit < 0:
            raise Exception("invalid search limit")
        if (addr == 0) ^ (size == 0):
            raise Exception("search address error")
        if addr != 0:
            return self.mem.search(pattern, addr, size, pattern_type, limit, verbose, onfound)
        else:
            retval = []
            mem_regions = [(m.addr, m.size, m.path) for m in self.maps if 'r' in m.perm]
            for addr, size, path in mem_regions:
                if verbose:
                    logger.info(f'searching size {size:08x}: {path}')
                remain_limit = 0
                if limit > 0:
                    remain_limit = limit - len(retval)
                idx = self.mem.search(pattern, addr, size, pattern_type, remain_limit, verbose, onfound)
                if idx:
                    retval.extend(idx)
                if 0 < limit <= len(retval):
                    break
            return retval

    def dump(self, file_path, output_path):
        regions = []
        for m in self.maps:
            if m.perm.startswith('---'):
                continue
            if '/' in file_path:
                if file_path == m.path:
                    regions.append(m)
            else:
                target = os.path.basename(m.path)
                if file_path == target:
                    regions.append(m)
        sorted_regions = sorted(regions, key=lambda k: k.offset)
        sorted_mem = []
        for m in sorted_regions:
            sorted_mem.append(self.mem.readbuf(m.addr, m.size))

        outdir = os.path.dirname(output_path)
        if outdir:
            os.makedirs(os.path.dirname(outdir), mode=0o755, exist_ok=True)
        fm = open(output_path, 'wb')
        fm.write(b'' * (sorted_regions[-1].offset + sorted_regions[-1].size))
        for i, m in enumerate(sorted_mem):
            fm.seek(sorted_regions[i].offset)
            fm.write(m)
        fm.close()

    @cached_property
    def libc(self):
        return cdll.LoadLibrary('libc.so')

    @cached_property
    def pagesize(self):
        return self.libc.getpagesize()

    def get_ptr_info(self, ptr) -> TUnion[MapInfo, None]:
        for m in self.maps:
            if m.addr <= ptr < (m.addr + m.size):
                return m
        return None

    def get_perm(self, ptr: int) -> str:
        """
        Get memory protection at ptr.
        :param ptr: address
        :return: str of 'rwxp' flags
        """
        self.update()
        info = self.get_ptr_info(ptr)
        if info:
            return info.perm
        else:
            return ''

    def set_perm(self, ptr: int, perm: str, size: int = 0) -> bool:
        """
        Set memory protection at ptr.
        :param ptr: address
        :param perm: protection string
        :param size: If set to non-zero, only relevant pages will be affected.
            Or by default, Protection of whole memory region will be updated. The latter one is recommended.
        :return: ok: bool
        """
        permbits = 0
        if 'r' in perm:
            permbits |= 0x1
        if 'w' in perm:
            permbits |= 0x2
        if 'x' in perm:
            permbits |= 0x4

        if size == 0:
            info = self.get_ptr_info(ptr)
            if info:
                retval = self.libc.mprotect(c_void_p(info.addr),
                                            c_void_p(info.size),
                                            c_void_p(permbits))
                self.update()
                return retval == 0
            else:
                return False
        else:
            aligned_addr = int(ptr / self.pagesize) * self.pagesize
            aligned_size = (ptr - aligned_addr) + size
            retval = self.libc.mprotect(c_void_p(aligned_addr), c_void_p(aligned_size), c_void_p(permbits))
            self.update()
            return retval == 0


class Memory:
    def __init__(self, pid, x64):
        self.pid = pid
        self.x64 = x64
        self.file = open(f'/proc/{pid}/mem', 'rb+', buffering=0)
        # redirect file I/O methods
        self.read = noexcept(self.file.read, b'')
        self.write = noexcept(self.file.write)
        self.seek = noexcept(self.file.seek)
        self.tell = noexcept(self.file.tell)
        self.readline = noexcept(self.file.readline, b'')

        # config
        self.bufsize = 128 * 1024 * 1024  # 128 MB

    def __del__(self):
        try:
            self.file.close()
        except:
            pass

    def readbuf(self, start_addr: int, size: int) -> bytes:
        prev_pos = self.tell()
        self.seek(start_addr)
        retval = self.read(size)
        self.seek(prev_pos)
        return retval

    def writebuf(self, start_addr: int, buf: bytes) -> int:
        prev_pos = self.tell()
        self.seek(start_addr)
        retval = self.write(buf)
        self.seek(prev_pos)
        return retval

    def readcstr(self, cstr_ptr, encoding='utf-8') -> str:
        """
        smartass helper, try to read string of struct { uint32_t length; char cstr[length]; }
        """
        prev_pos = self.tell()
        self.seek(cstr_ptr)
        retval = b''
        # max length: self.bufsize
        for i in range(0, int(self.bufsize / 1024)):
            # 1KB buf
            buf = self.read(1024).split(b'\x00', 1)
            retval += buf[0]
            if len(buf) > 1:
                break
        self.seek(prev_pos)
        return retval.decode(encoding, errors='ignore')

    def search(self, pattern: Union(str, bytes), addr: int, size: int, pattern_type: str = '', limit: int = 1,
               verbose: bool = False, onfound: Callable = None) -> list:
        """
        :param limit: 0: inf, >=1: break on limit
        :param pattern: if pattern_type is 'aob', wildcard '??' is supported
        :param pattern_type: specify 'aob'/'str' for string, 'double' for double, or '[u]int[32/64]' for integer.
            pass empty str if the pattern is a literal of basic type (str, bytes, float)
        :param onfound: onfound(addr) -> bool, return True to break searching
        """
        if limit < 0:
            return []

        retval = []
        target, mask = self._pattern_to_bytes(pattern, pattern_type)
        if not target:
            return []

        prev_pos = self.tell()
        self.seek(addr)
        current_start_addr = addr
        remained_size = size
        # merge with last buf in case pattern split by boundary
        last_buf = None
        while remained_size > 0:
            readsize = self.bufsize if self.bufsize >= remained_size else remained_size
            buf = self.read(readsize)
            remained_size -= readsize
            merged_buf = buf
            offset = 0
            if last_buf:
                offset -= len(target)
                merged_buf = last_buf[offset:] + buf

            start_offset = 0
            while (limit == 0) or (len(retval) < limit):
                found_idx = pattern_search(merged_buf, target, mask, start_offset)
                if found_idx < 0:
                    break
                found_addr = current_start_addr + found_idx + offset
                retval.append(found_addr)
                if verbose:
                    logger.info(f'    found: 0x{found_addr:x}')
                if onfound:
                    if onfound(found_addr):
                        break
                start_offset += (found_idx + 1)
            last_buf = buf
            current_start_addr += len(buf)
            if len(buf) != readsize:
                break
        self.seek(prev_pos)
        return retval

    def _pattern_to_bytes(self, pattern, pattern_type) -> (bytes, tuple):
        pt = pattern_type.lower()
        if isinstance(pattern, (bytes, str)):
            if pt == 'aob' or pt == 'array of bytes':
                trimed_pattern = pattern.replace(' ', '').replace('\t', '')
                if len(trimed_pattern) % 2 != 0 or not re.fullmatch('[0-9a-fA-F?]*', trimed_pattern):
                    raise Exception("invalid search pattern")
                masks = []
                for i in range(0, len(trimed_pattern), 2):
                    if (trimed_pattern[i] == '?') ^ (trimed_pattern[i + 1] == '?'):
                        raise Exception("invalid search pattern")
                    if (trimed_pattern[i] == '?') and (trimed_pattern[i + 1] == '?'):
                        masks.append(int(i / 2))
                pattern_hex = trimed_pattern.replace('?', '0')
                return bytes.fromhex(pattern_hex), tuple(masks)
            else:
                if isinstance(pattern, bytes):
                    return pattern, ()
                else:
                    if not pattern_type:
                        pattern_type = 'utf-8'
                    return bytes(pattern, encoding=pattern_type), ()
        elif isinstance(pattern, int):
            x64 = self.x64
            if '32' in pt:
                x64 = False
            elif '64' in pt:
                x64 = True
            if x64:
                if 'u' in pt:
                    return struct.pack('<Q', pattern), ()
                else:
                    return struct.pack('<q', pattern), ()
            else:
                if 'u' in pt:
                    return struct.pack('<L', pattern), ()
                else:
                    return struct.pack('<l', pattern), ()
        elif isinstance(pattern, float):
            if pt == 'double':
                return struct.pack("<d", pattern), ()
            else:
                return struct.pack("<f", pattern), ()
        else:
            raise Exception("unknown pattern type")


class Flags:
    @staticmethod
    def get(flag: str) -> str:
        fp = f'/proc/sys/{flag}'
        if os.path.exists(fp):
            return Path(fp).read_text()
        else:
            return ''

    @staticmethod
    def set(flag: str, value: TUnion[int, str]):
        if not isinstance(value, str):
            value = str(value)
        fp = f'/proc/sys/{flag}'
        if os.path.exists(fp):
            Path(fp).write_text(value)
            return True
        else:
            return False
