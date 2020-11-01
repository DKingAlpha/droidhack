# DroidHack
A toolkit that provides easy access with procfs and devfs

## How to use

First, follow the guide I provided in `Setup` section, so you can run/debug your python code in any rooted android system (real system, NOT chrooted)

After python dev env being successfully setup, this python package will empower you to control your android phone fully by python.

With this package, you can:
* search/edit process memory in your phone
* read opcodes in a process
* dump a module from a running process

With python dev env, you can (DIY):
* run system calls and library functions with `ctypes`, e.g libc
* do any other cool stuffs based on syscalls and libraries.


See the following code snippets for other usages.
```python
from droidhack.procfs import *

procs = Processes()
qq = procs.get('com.tencent.mobileqq')
qq.dump('libDBEncryptV2.so', '/data/local/tmp/libDBEncryptV2.so')
```

Search memory by region. Searching by AOB is supported
```python
result = qq.search(pattern='<Any Chat Text Here>', verbose=True)
for ptr in result:
    print(qq.get_ptr_info(ptr))
    print(qq.mem.readstring(ptr))

for m in qq.maps:
    if '.so' in m['path'] and 'r-' in m['perm']:
        print(m)
        # advanced usage
        copyright_addrs = qq.search(pattern="copyright", addr_start=m['addr'][0], addr_end=m['addr'][1],
                                    limit=1)
        for ca in copyright_addrs:
            print(qq.mem.readstring(ca))
```

Interactive searching
```python
candidates = qq.search(int(input('current value:')), limit=0, verbose=True)
while True:
    cand = []
    for c in candidates:
        if qq.search(pattern=int(input('current value:')), addr_start=c, addr_end=c+4):
            cand.append(c)
    candidates = cand
    print(f'found {len(candidates)} results.')
    if len(candidates) < 10:
        break

# play with found candidates
pass
```


## Setup
GTFO if you cant understand steps below.

DO NOT FOLLOW THE STEPS UNLESS YOU REALLY UNDERSTAND THEM.\
or you might just fuck up your phone.

### Android Side:
1. Download & install termux on your **ROOTED** android system
2. Verify root by running `su` in termux. Remember root for termux so magisk automatically allow root requests.
3. In termux, install packages by running `pkg install tsu openssh python`
4. In termux, configure openssh by:
    * writing your public key to `~/.ssh/authorized_keys`
    * edit `~/../usr/etc/ssh/sshd_config`, append `StrictModes no` and `AllowTcpForwarding yes`
5. In termux, run `tsu` to enter su with termux envs, then run `sshd` to start openssh server as root.

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
