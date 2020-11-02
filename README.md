# DroidHack
A toolkit that provides easy access with procfs and devfs

## How to use

First, follow the guide I provided in `Setup` section, so you can run/debug your python code in any rooted android system (real system, NOT chrooted)

After python dev env being successfully setup, this python package will empower you to control your android phone fully by python.

With this package, you can:
* search/edit process memory in your phone
* read/write opcodes in a process, or hook them.
* dump a module from a running process

With python dev env, you can (DIY):
* run system calls and library functions with `ctypes`, e.g libc
* do any other cool stuffs based on syscalls and libraries.


## Setup
GTFO if you cant understand steps below.

DO NOT FOLLOW THE STEPS UNLESS YOU REALLY UNDERSTAND THEM.\
or you might just fuck up your phone.

### Android Side:
1. Download & install termux on your **ROOTED** android system
2. Verify root by running `su` in termux. Remember root for termux so magisk automatically allow root requests.
3. In termux, install packages by running `pkg install tsu openssh python cmake clang`
4. In termux, configure openssh by:
    * writing your public key to `~/.ssh/authorized_keys`
    * edit `~/../usr/etc/ssh/sshd_config`, append `StrictModes no` and `AllowTcpForwarding yes`
5. In termux, run `tsu` to enter su with termux envs, then run `sshd` to start openssh server as root.
6. In termux, run `pip install droidhack`

### PC Side
1. Install PyCharms
2. Settings -> Deployment, setup your remote android ssh server here.
    * Server: `ssh root@<android_ip> -p 8022`
    * Root Path: `/`
    * Deployment Path: `/data/local/tmp/your_project` or something similar
3. Settings -> Project -> Python Interpreter: add deployment target with python interpreter path: `/data/data/com.termux/files/usr/bin/python`
4. Debug your pycharm project with remote python interpreter created above.

#### Note
If you have trouble connecting by remote ip address of android phone,
`adb forward tcp:8022 tcp:8022` will forward 8022 port from remote to your local address.
So you can connected to `127.0.0.1:8022` instead.

PyCharms 2020.1 has a bug in `.pycharm_helper`, remember to fix the bug manually.


## Usage
```python
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

```
