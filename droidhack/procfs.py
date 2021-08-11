import re
import os
import struct
from ctypes import *
from typing import Union as TUnion, Callable
import pathlib

from ._utils import *

__all__ = ['Processes', 'Process', 'Memory', 'Flags', 'MapInfo', 'SMapInfo']


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
            if not all:
                # not found
                return None
            else:
                return tuple(retval)
        elif isinstance(pid_or_cmd, str):
            retval = []
            for i in self.procs:
                if re.fullmatch(pid_or_cmd, ' '.join(i.cmdline)):
                    if not all:
                        return i
                    retval.append(i)
            if not all:
                # not found
                return None
            else:
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

    def __init__(self, proc, index):
        super().__init__()
        self.proc = proc
        self.index = index

    def prev(self, i=1):
        return self.proc.maps[self.index-i]

    def next(self, i=1):
        return self.proc.maps[self.index+i]

    def __repr__(self):
        return f"{self.addr:x}-{self.addr+self.size:x}, size: {self.size:x}, offset: {self.offset:08x} {self.perm} {self.path}"


class SMapInfo(dict):
    """
    members (case-insensitive):
        addr, size, perm, path, offset, dev, inode
        name, kernelpagesize, mmupagesize, rss, pss,
        referenced, anonymous, anonHugePages
        vmflags ...

    usage:
        m.addr or m['addr']
    """
    def __init__(self, proc, index):
        super().__init__()
        self.proc = proc
        self.index = index
        __setattr__ = self.__setitem__
        __delattr__ = self.__delitem__

    def __setitem__(self, key, value):
        assert isinstance(key, str)
        return super().__setitem__(key.lower(), value)

    def __delitem__(self, key):
        assert isinstance(key, str)
        return super().__delitem__(key.lower())

    def __getattr__(self, item):
        return super().get(item.lower())

    def prev(self, i=1):
        return self.proc.maps[self.index-i]

    def next(self, i=1):
        return self.proc.maps[self.index+i]

    def __repr__(self):
        return f"addr: {self.addr:x}, size: {self.size:x}, offset: {self.offset:08x} {self.perm} {self.path}"


class Process:
    """
    Process() returns current process
    """
    def __init__(self, pid=0):
        if pid == 0:
            pid = os.getpid()
        self.pid = pid
        self.maps_config = {
            'maxsplit': 5,
            'index': {'addr': 0, 'perm': 1, 'offset': 2, 'dev': 3, 'inode': 4, 'path': 5}
        }
        self.cache = {}
        self.invalid = False

    def __repr__(self):
        return f'[{self.pid}] {"".join(self.cmdline)}'

    def update(self, prop=''):
        """
        :param prop: leave blank to clean all caches
        """
        if prop:
            self.cache.pop(prop, None)
        else:
            self.cache = {}

    @cached_property
    def x64(self) -> bool:
        tmp = open(f'/proc/{self.pid}/maps', 'r')
        addrs = tmp.readlines()[-1].rstrip().split()[self.maps_config['index']['addr']].split('-')
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
        cmdline_content = pathlib.Path(f'/proc/{self.pid}/cmdline').read_text()
        if not cmdline_content:
            return ()
        cmdlines = cmdline_content.split('\x00')
        return tuple([c for c in cmdlines if c != ''])

    @cached_proc_property
    def smaps(self) -> list:
        def handle_block(block, index):
            sinfo = SMapInfo(self, index)
            mapinfo = self._maps_line_to_mapinfo(block.pop(0), index)
            for k in mapinfo:
                sinfo[k] = mapinfo[k]
            for i in block:
                data = i.split(':', 1)
                k = data[0].lower()
                if k == 'name':
                    v = data[1].lstrip()
                elif k == 'vmflags':
                    v = data[1].strip().split()
                else:
                    v_size = data[1].lstrip().split()
                    assert v_size[1] == 'kB'
                    v = int(v_size[0]) * 1024
                sinfo[k] = v
            return sinfo
        index = 0
        retval = []
        current_block = []
        smaps_content = pathlib.Path(f'/proc/{self.pid}/smaps').read_text()
        if not smaps_content:
            return []
        start_pattern = re.compile(r'[0-9a-fA-F]+-[0-9a-fA-F]+\s[rwxsp-]*\s.*')
        for m in smaps_content.splitlines():
            m = m.rstrip()
            if start_pattern.fullmatch(m):
                if current_block:
                    retval.append(handle_block(current_block, index))
                    index += 1
                    current_block = []
            current_block.append(m)
        return retval

    def _maps_line_to_mapinfo(self, line, index):
        minfo = line.rstrip().split(maxsplit=self.maps_config['maxsplit'])
        mm = MapInfo(self, index)
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
        return mm

    @cached_proc_property
    def maps(self) -> list:
        maps_content = pathlib.Path(f'/proc/{self.pid}/maps').read_text()
        if not maps_content:
            return []
        retval = []
        index = 0
        for m in maps_content.splitlines():
            retval.append(self._maps_line_to_mapinfo(m, index))
            index += 1

        return retval

    @cached_proc_property
    def mem(self):
        return Memory(self.pid, self.x64)

    def search(self, pattern:str, addr:int=0, size:int=0, pattern_type:str='', limit:int=1,
               verbose:bool=False, onfound:Callable=None) -> list:
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

    def dump(self, start, size, output_path):
        """
        dump momory to file
        :param start: address or filename to dump
        :param size: set size = 0 to read until memory became noncontinuous
        :param output_path:
        """
        if isinstance(start, str):
            target = None
            for i in self.maps:
                if 'x' in i.perm and i.path.endswith(start) and i.offset == 0:
                    target = i.addr
            if target:
                start = target
            else:
                raise Exception('dump file not found')

        outdir = os.path.dirname(output_path)
        if outdir:
            os.makedirs(os.path.dirname(outdir), mode=0o755, exist_ok=True)
        fm = open(output_path + f'_0x{start:x}', 'wb')

        if size == 0:
            current_region = self.get_ptr_info(start)
            idx = self.maps.index(current_region)
            has_written_zero = None
            for i in range(idx, len(self.maps)):
                if (self.maps[i].addr + self.maps[i].size) != self.maps[i+1].addr:
                    break
                m = self.maps[i]
                dumped = self.mem.readbuf(start, size)
                if m.offset == 0:
                    if has_written_zero:
                        raise Exception(f'duplicate file offset 0: {has_written_zero} <=> {m}')
                    has_written_zero = m
                fm.seek(m.offset)
                fm.write(dumped)
        else:
            dumped = self.mem.readbuf(start, size)
            fm.write(dumped)
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

    def find_code_cave(self, size, perm:str='r-x', start_from:int=0, not_addrs:tuple=()):
        if start_from:
            start_from = self.get_ptr_info(start_from)
        aligned_size = (int(size / 4) + 1) * 4      # align to addr
        for i in self.maps:
            if start_from:
                if i != start_from:
                    continue
                else:
                    start_from = False
            if i.inode != 0 or (not i.perm.startswith(perm)) or i.size <= aligned_size:
                continue
            inspect_addr = i.addr + i.size - aligned_size
            if self.mem.readbuf(inspect_addr, aligned_size) == (b'\x00' * aligned_size):
                if inspect_addr not in not_addrs:
                    return inspect_addr
        return 0

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
        if os.getpid() != self.pid:
            raise Exception("set perm is only available for self process")

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

    def load_library(self, arch, libso, libc_time_offset, libc_dlopen_offset):
        """
        Load library by hooking time() to a stub that calls dlopen to load library
        :param arch: currently arm64 only
        :param libso: so filename or path to load.
        :param libc_time_offset: time function offset to libc
        :param libc_dlopen_offset: dlopen function offset to libc
        """
        try:
            import keystone
            asm = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

            has_runned_flag_addr = self.find_code_cave(4, perm='rw')
            if has_runned_flag_addr == 0:
                raise Exception('failed to find data cave')
            # print(f'has_runned_flag_addr: {has_runned_flag_addr:x}, {victim.get_ptr_info(has_runned_flag_addr)}')

            #### get the payload length with random address
            shellcode_len = 0
            if arch == 'arm64':
                shellcode_len = len(asm.asm(self.get_dlopen_payload_arm64(0, 0, 0 , libso),
                                        addr=0, as_bytes=True)[0])
            else:
                raise Exception('load library only support arm64 currently')
            
            if shellcode_len == 0:
                raise Exception('failed to generate payload')
            #### now find a code cave
            shellcode_addr = self.find_code_cave(shellcode_len, not_addrs=(has_runned_flag_addr,))
            if shellcode_addr == 0:
                raise Exception('failed to find code cave')
            # print(f'shellcode_addr: {shellcode_addr:x}, {victim.get_ptr_info(shellcode_addr)}')

            #### get the real payload
            time_addr = self.find('/libc.so')[0].addr + libc_time_offset
            dlopen_addr = self.mem.readptr(self.find('/libc.so')[0].addr + libc_dlopen_offset)
            shellcode = asm.asm(self.get_dlopen_payload_arm64(time_addr, has_runned_flag_addr, dlopen_addr, libso),
                                addr=shellcode_addr, as_bytes=True)[0]

            trampoline = asm.asm(f"""
            b #{shellcode_addr}
            """, addr=time_addr, as_bytes=True)[0]
            # prepare stub
            self.mem.writebuf(shellcode_addr, shellcode)
            # detour
            self.mem.writebuf(time_addr, trampoline)
            return True
        except ImportError:
            print('python dependency keystone is required')
            return False

    def get_dlopen_payload_arm64(self, hook_addr, flag_addr, dlopen_addr, library):
        orig_ins_as_u32 = self.mem.readptr(hook_addr, 4)
        return f"""
            sub sp, sp, #0x40
            stp x29, x30, [sp]
            stp x0, x1, [sp, #0x10]
            stp x2, x3, [sp, #0x20]
            adr x1, flag_ptr
            ldr x0, [x1]
            ldr x1, [x0]
            cmp x1, 0
            bne return_to_caller
            // mark runned
            mov x1, 1
            str x1, [x0]
            // run
            adr x0, library_to_load
            mov x1, #0x101
            bl #{dlopen_addr}
            cmp x0, 0
            bne return_to_caller
            // x0 == 0, something wrong, crash now
        return_to_caller:
            ldp x29, x30, [sp]
            ldp x0, x1, [sp, #0x10]
            ldp x2, x3, [sp, #0x20]
            add sp, sp, #0x40
        orig_ins:
            .4byte {orig_ins_as_u32}
            b #{hook_addr+4}
    
        flag_ptr:
            .8byte {flag_addr}
    
        library_to_load:
            .string "{library}"
        """

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

    def readptr(self, addr: int, size=0) -> int:
        if size == 0:
            if self.x64:
                size = 8
            else:
                size = 4
        if size == 8:
            buf = self.readbuf(addr, 8)
            ptr = struct.unpack('<Q', buf)[0]
            return ptr
        elif size == 4:
            buf = self.readbuf(addr, 4)
            ptr = struct.unpack('<L', buf)[0]
            return ptr
        else:
            raise Exception("unknown size for readptr")

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

    def search(self, pattern: TUnion[str, bytes], addr: int, size: int, pattern_type: str = '', limit: int = 1,
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
            readsize = self.bufsize if remained_size >= self.bufsize else remained_size
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

    def _pattern_to_bytes(self, pattern, pattern_type):
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
            return pathlib.Path(fp).read_text()
        else:
            return ''

    @staticmethod
    def set(flag: str, value: TUnion[int, str]):
        if not isinstance(value, str):
            value = str(value)
        fp = f'/proc/sys/{flag}'
        if os.path.exists(fp):
            pathlib.Path(fp).write_text(value)
            return True
        else:
            return False
