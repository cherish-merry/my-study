import pandas as pd
import numpy as np
import sys

file = '/media/ckz/T7/datasets/LOCAL/csv/slowhttptest.pcap_Flow.csv'

file_out = '/media/ckz/T7/datasets/CICIDS2017/monday/csv/Monday-WorkingHours.pcap_ISCX.csv'

# print(sys.maxsize)
# 15000000 1000000
if __name__ == '__main__':
    df = pd.read_csv(file_out)
    print(df.shape)
    df = df.dropna()
    print(df.shape)
    df = df.drop(df[df[' Flow Duration'] < 10].index)
    print(df.shape)

    # df = df.drop(df[df[' Flow Duration'] < 15000000].index)
    # print(df.shape)

    df = df.drop(df[df[' Idle Max'] < 1000000].index)
    print(df.shape)
# df.to_csv(file_out, encoding="utf_8_sig", index=False)
