import numpy as np
import matplotlib.pyplot as plt

# 创建一个数组0-100，数据间隔是0.1
x = np.arange(0, 100, 0.1)

y = x ** 2

# 调用subplots函数
# 指定图像分辨率、大小和长宽比例
# 创建一个800*600像素、100dpi(每英寸100点)分辨率的图形
# 返回一个画布对象和一个轴数组
fig, axe = plt.subplots(figsize=(4, 3), dpi=100)

# 在axe上绘制一条抛物线，红色 点
axe.plot(x, y, "r:")
# 设置x轴标记为X
axe.set_xlabel("X")
# 设置Y轴标记为Y
axe.set_ylabel("Y")

# 设置图标题
axe.set_title("y=x**2")

# 显示绘制的图片
plt.show()
