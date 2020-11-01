from droidhack.procfs import *
from droidhack.devfs import *

procs = Processes()
qq = procs.get('com.tencent.mobileqq')
qq.dump('libDBEncryptV2.so', '/data/local/tmp/libDBEncryptV2.so')

result = qq.search(pattern='<Any Chat Text Here>')
for ptr in result:
    print(qq.get_ptr_info(ptr))
    print(qq.mem.readstring(ptr))

for m in qq.maps:
    if '.so' in m['path'] and 'r-' in m['perm']:
        print(m)
        # advanced usage
        copyright_addrs = qq.search(pattern="copyright", addr_start=m['addr'][0], addr_end=m['addr'][1],
                                    limit=1, verbose=True)
        for ca in copyright_addrs:
            print(qq.mem.readstring(ca))

kmem = DevKmem()
sys_open_addr = kmem.get_sym('sys_open')[0]['addr']
print(f'{sys_open_addr:x}')

candidates = []
while True:
    candidates = qq.search(pattern=1234, limit=0, verbose=True)
    print(f'found {len(candidates)} results.')
    if len(candidates) < 10:
        break

# play with found candidates
pass
