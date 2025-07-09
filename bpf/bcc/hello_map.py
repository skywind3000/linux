#! /usr/bin/python3
import time
import bcc

program = r'''
BPF_HASH(counter_map);

int hello(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;
    uid = bpf_get_current_uid_gid() & 0xffffffff;
    p = counter_map.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_map.update(&uid, &counter);
    return 0;
}
'''

b = bcc.BPF(text = program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event = syscall, fn_name = 'hello')

while True:
    time.sleep(2)
    s = ''
    for k, v in b['counter_map'].items():
        s += f'ID {k.value}: {v.value}\n'
    print(s)


