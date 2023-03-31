import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split


def label(s):
    if s == "BENIGN":
        return 0
    if s == "DoS":
        return 1
    if s == "portScan":
        return 2
    if s == "bruteForce":
        return 3
    if s == "ddos":
        return 4
    if s == "heartbleed":
        return 5
    if s == "infiltration":
        return 6
    if s == "Web Attack":
        return 7
    if s == "botnet":
        return 8


df = pd.read_csv("CICIDS2017-15s.csv")
print(df.columns)
df = df.drop("Time", axis=1)
counts = df['Label'].value_counts()
print("-----")
print(counts)
