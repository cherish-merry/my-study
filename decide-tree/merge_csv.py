import pandas as pd
import os

folder_path = '/media/ckz/T7/datasets/merge'
res_path = '/media/ckz/T7/datasets/merge'
merge_name = 'all.csv'

file_list = os.listdir(folder_path)
df = pd.read_csv(folder_path + "/" + file_list[0])

df.to_csv(res_path + "/" + merge_name, encoding="utf_8_sig", index=False)

# 循环遍历列表中各个CSV文件名，并追加到合并后的文件
for i in range(1, len(file_list)):
    df = pd.read_csv(folder_path + "/" + file_list[i])
    df.to_csv(res_path + "/" + merge_name, encoding="utf_8_sig", index=False, header=False, mode='a+')
