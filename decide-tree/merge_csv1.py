import pandas as pd
import os

folder_path = '/media/ckz/T7/datasets/CICIDS2017-Processed/wednesday/csv'
res_path = '/media/ckz/T7/datasets/CICIDS2017-Processed/csv/day'
merge_name = 'wednesday.csv'

file_list = os.listdir(folder_path)
df = pd.read_csv(folder_path + "/" + file_list[0])

df.to_csv(res_path + "/" + merge_name, encoding="utf_8_sig", index=False)

# 循环遍历列表中各个CSV文件名，并追加到合并后的文件
for i in range(1, len(file_list)):
    print(file_list[i])
    df = pd.read_csv(folder_path + "/" + file_list[i])
    df.to_csv(res_path + "/" + merge_name, encoding="utf_8_sig", index=False, header=False, mode='a+')
