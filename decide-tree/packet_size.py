import numpy as np
import matplotlib.pyplot as plt

"""
    x,y:表示坐标值上的值
    string:表示说明文字
    fontsize:表示字体大小
    verticalalignment：垂直对齐方式 ，参数：[ ‘center’ | ‘top’ | ‘bottom’ | ‘baseline’ ]
    horizontalalignment：水平对齐方式 ，参数：[ ‘center’ | ‘right’ | ‘left’ ]
    xycoords选择指定的坐标轴系统:
    figure points：图左下角的点
    figure pixels：图左下角的像素
    figure fraction：图的左下部分
    axes points：坐标轴左下角的点
    axes pixels：坐标轴左下角的像素
    axes fraction：左下轴的分数
    data：使用被注释对象的坐标系统(默认)
    polar(theta,r)：if not native ‘data’ coordinates t
    arrowprops #箭头参数,参数类型为字典dict
    width：箭头的宽度(以点为单位)
    headwidth：箭头底部以点为单位的宽度
    headlength：箭头的长度(以点为单位)
    shrink：总长度的一部分，从两端“收缩”
    facecolor：箭头颜色
    bbox给标题增加外框 ，常用参数如下：
    boxstyle：方框外形
    facecolor：(简写fc)背景颜色
    edgecolor：(简写ec)边框线条颜色
    edgewidth：边框线条大小
"""
name_list = ['64', "200", '800', '1200', '1500']

normal = [1.682, 1.314, 1.17, 0.997, 0.804]
snort2 = [1.256, 1.082, 0.944, 0.92, 0.783]
snort3 = [1.108, 0.849, 0.796, 0.744, 0.716]
xdp = [1.409, 1.155, 0.908, 0.806, 0.804]
x_width = 0.4  # 调节横宽度
x = [0, x_width, 2 * x_width, 3 * x_width, 4 * x_width]
total_width, n = 0.32, 4
width = total_width / n
fontsize = 8  # 字体大小
fig = plt.figure(figsize=(5.3, 4.3), dpi=300, facecolor='white', edgecolor="white")  # figsize长、宽
axes = plt.subplot(111)
axes.bar(x, snort2, width=width, label='Snort2.9', hatch='\\\\\\', color='white',
         edgecolor='aquamarine')  # hatch：填充图案，edgecolor：填充图案颜色，color：柱形图颜色
# 给柱形图加上values
# for a, b in zip(x, snort2):
#     axes.text(a, b + 0.028, '%.4f' % b, ha='center', verticalalignment="top", fontsize=fontsize)

for i in range(len(x)):
    x[i] = x[i] + width
axes.bar(x, snort3, width=width, label='Snort3', tick_label=name_list, hatch='///', color="white",
         edgecolor='lightgreen')
# for a, b in zip(x, snort3):
#     axes.text(a, b + 0.028, '%.4f' % b, ha='center', verticalalignment="top", fontsize=fontsize)

for i in range(len(x)):
    x[i] = x[i] + width
axes.bar(x, xdp, width=width, label='XDP', tick_label=name_list, hatch='//', color="white",
         edgecolor='mediumpurple')
# for a, b in zip(x, xdp):
#     axes.text(a, b + 0.028, '%.4f' % b, ha='center', verticalalignment="top", fontsize=fontsize)

for i in range(len(x)):
    x[i] = x[i] + width
axes.bar(x, normal, width=width, label='Normal', tick_label=name_list, hatch='\\\\', color="white",
         edgecolor='pink')
# for a, b in zip(x, normal):
#     axes.text(a, b + 0.028, '%.4f' % b, ha='center', verticalalignment="top", fontsize=fontsize)

axes.set_ylim(0.4, 1.8)
plt.xticks(np.asarray([0, x_width, 2 * x_width, 3 * x_width, 4 * x_width]) + width * 1.5,
           name_list)  # 调节横坐标不居中

font1 = {
    # 'family': 'Times New Roman',  # 字体
    # 'weight': 'normal',
    'size': fontsize  # 字体大小
}
plt.tick_params(labelsize=fontsize)
plt.legend(loc="upper right", prop=font1)  # 图例位置、大小
plt.ylabel('Mpps', font1)  # 纵坐标大小、字体

plt.savefig("packet_size.svg", dpi=300, format="svg")
plt.show()
