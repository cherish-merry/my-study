import matplotlib.pyplot as plt

pkt_size = [64, 200, 400, 600, 800, 1000, 1200, 1400, 1500]

throughput = [826, 2143, 3770, 5666, 7340, 9044, 9564, 9612, 9667]

xdp_throughput = [698, 1792, 2882, 4263, 5660, 6648, 7535, 8780, 9413]

snort3_throughput = [541, 1323, 2566, 3847, 5006, 5876, 7028, 8008, 8352]

plt.figure(dpi=500)
plt.grid(linestyle="--")  # 设置背景网格线为虚线
ax = plt.gca()
ax.spines['top'].set_visible(False)  # 去掉上边框
ax.spines['right'].set_visible(False)  # 去掉右边框

ax.set_xlabel('Packet Length(bytes)')
ax.set_ylabel('Maximum Throughput(Mbps)')
ax.plot(pkt_size, throughput, color="#A1A9D0", marker='o')
ax.plot(pkt_size, xdp_throughput, color="#F0988C", marker='<')
ax.plot(pkt_size, snort3_throughput, color="#B883D4", marker='*')
ax.tick_params(axis='y')

plt.legend(['Normal', 'XR-IDS', "Snort3"])  # 设置折线名称

plt.savefig("throughput.svg", dpi=500, format="svg")

plt.show()
