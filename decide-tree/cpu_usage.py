import matplotlib.pyplot as plt

pps = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.6, 1.7]

xdp_pps = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.45]

snort3_pps = [0.2, 0.4, 0.6, 0.8, 1.0, 1.07]

cpu_usage_rate = [40.4, 45.2, 61.9, 83.7, 90.5, 98.2, 101.6, 101.5, 102.5]

xdp_cpu_occupy_rate = [41.4, 46.6, 66.2, 88.4, 95.7, 101.9, 101.8, 102.3]

snort3_cpu_usage_rate = [56.2, 87.7, 116.9, 158.3, 164.1, 162.3]

plt.figure(dpi=300)
plt.grid(linestyle="--")  # 设置背景网格线为虚线
ax = plt.gca()
ax.spines['top'].set_visible(False)  # 去掉上边框
ax.spines['right'].set_visible(False)  # 去掉右边框

ax.set_xlabel('Mpps')
ax.set_ylabel('Single-core Cpu Usage(%)')
ax.plot(pps, cpu_usage_rate, color="blue", marker='o')
ax.plot(xdp_pps, xdp_cpu_occupy_rate, color="orange", marker='<')
ax.plot(snort3_pps, snort3_cpu_usage_rate, color="red", marker='*')
ax.tick_params(axis='y')

plt.legend(['Normal', 'XDP', "Snort3"])  # 设置折线名称
plt.show()
