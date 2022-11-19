import matplotlib.pyplot as plt

# marker：.  ,   o   v    <    *    +    1

# 创建模拟数据

pps = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.6, 1.7]

xdp_pps = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.45]

snort3_pps = [0.2, 0.4, 0.6, 0.8, 1.0, 1.07]

snort2_pps = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2]

drop_packet_rate = [0, 0, 0.15, 0.36, 1.18, 1.53, 12.4, 23.7, 28.6]

xdp_drop_packet_rate = [0, 0, 0.23, 0.73, 1.51, 14, 26.8, 29.4]

snort3_drop_packet_rate = [0, 0.06, 0.33, 3.44, 20.4, 26.4]

snort2_drop_packet_rate = [0, 0, 0.2, 1.5, 7, 26.2]

plt.figure(dpi=300)
plt.grid(linestyle="--")  # 设置背景网格线为虚线


ax = plt.gca()
ax.spines['top'].set_visible(False)  # 去掉上边框
ax.spines['right'].set_visible(False)  # 去掉右边框

ax.set_xlabel('Mpps')
ax.set_ylabel('Drop Packet Rate(%)')
ax.plot(pps, drop_packet_rate, color="blue", marker='o')
ax.plot(xdp_pps, xdp_drop_packet_rate, color="orange", marker='<')
ax.plot(snort3_pps, snort3_drop_packet_rate, color="red", marker='*')
ax.plot(snort2_pps, snort2_drop_packet_rate, color="green", marker='.')
ax.tick_params(axis='y')

plt.legend(['Normal', 'XDP', "Snort3", "Snort2.9"])  # 设置折线名称

plt.savefig("drop_packet.svg", dpi=300, format="svg")
plt.show()
