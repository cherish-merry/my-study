#!/usr/bin/python3

from bcc import BPF
import time

device = "enp3s0"
b = BPF(src_file="program.c")
fn = b.load_func("my_program", BPF.XDP)
b.attach_xdp(device, fn, 0)
packet_cnt = b.get_table("packet_cnt")
print("hit CTRL+C to stop")
while 1:
    try:
        for k, v in packet_cnt.items():
            print("protocol:", k, "count:", v)
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
