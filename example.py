from capstone import *
from keystone import *
from droidhack.procfs import *
from droidhack.devfs import *

# get a random process
procs = Processes()
msg = procs.find('messaging')
assert len(msg) > 0
msg = msg[0]
# dump a module
msg.dump('libopenjdk.so', '/data/local/tmp/libopenjdk.so')

# search the whole memory
google_msg_ptrs = msg.search(pattern="GNU", limit=5, verbose=False)
for ptr in google_msg_ptrs:
    print(msg.mem.readcstr(ptr).replace('\r', '\n'))

# search memory by module
for m in msg.maps:
    if '.so' in m.path and 'r-' in m.perm:
        # advanced usage
        copyright_addrs = msg.search(pattern="CREATE ", addr=m.addr, size=m.size, limit=1)
        if copyright_addrs:
            print(m.path)
        for ca in copyright_addrs:
            print('    ' + msg.mem.readcstr(ca))


# patch code dynamically
asm = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
dism = Cs(CS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
opcodes = """
    MOV             X19, X0
    MOV             X20, X1
"""
target_codes = asm.asm(opcodes, as_bytes=True)[0]
print(f'finding {opcodes}    => {target_codes}')
possible_targets = msg.search(pattern=target_codes, verbose=True)
# possible_targets = qq.search(pattern=bytearray(target_opcodes).hex(), pattern_type='aob') # example for AOB search
for ptr in possible_targets:
    print(f'found at {ptr:x}, region: {msg.get_ptr_info(ptr)}\ndumping opcodes:')
    for i in dism.disasm(msg.mem.readbuf(ptr, 4 * 4), offset=ptr):
        print(i)
    print('hacking...')
    old_perm = msg.get_perm(ptr)
    msg.set_perm(ptr, 'rwx')
    old_opcodes = msg.mem.readbuf(ptr + 4 * 2, 4)
    msg.mem.writebuf(ptr + 4 * 2, asm.asm('mov x0, x1', as_bytes=True)[0])
    print(f'modified instructions at {ptr:x}, dumping opcodes:')
    for i in dism.disasm(msg.mem.readbuf(ptr, 4 * 4), offset=ptr):
        print(i)
    # restore opcodes
    msg.mem.writebuf(ptr + 4 * 2, old_opcodes)
    print('restore perm')
    msg.set_perm(ptr, old_perm)
    print(f'current ptr info: {msg.get_ptr_info(ptr)}')


# interactive search
candidates = msg.search(int(input('current value:')), limit=0, verbose=True)
while True:
    cand = []
    for c in candidates:
        if msg.search(pattern=int(input('current value:')), addr=c, size=4):
            cand.append(c)
    candidates = cand
    print(f'found {len(candidates)} results.')
    if len(candidates) < 10:
        break

# play with found candidates
pass


# [[unlikely]] RKmem operation
kmem = DevKmem()
sys_open_addr = kmem.get_sym('sys_open')[0].addr
print(f'{sys_open_addr:x}')
