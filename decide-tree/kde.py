import pandas as pd
import numpy as np
import matplotlib

matplotlib.use('qtagg')
import matplotlib.pyplot as plt
import seaborn as sns


def label(s):
    if s == "BENIGN":
        return 0
    else:
        return 1


if __name__ == '__main__':
    df = pd.read_csv("dataset/CICIDS.csv",
                     converters={"Label": label})
    df = df.drop(['Init Fwd Win Byts'], axis=1)
    df = df.drop(['URG Flag Cnt'], axis=1)
    df = df.drop(['Protocol'], axis=1)

    df1 = df.drop(df[df['Label'] == 0].index)

    print("normal flow:", df1.shape)

    df2 = df.drop(df[df['Label'] == 1].index)

    print("attack flow", df2.shape)

    columns = np.array(df.columns)
    print(columns)

    plt.figure(figsize=(8, 6), dpi=300)
    plt.subplot(1, 2, 1)
    sns.kdeplot(data=df1, x="Pkt Len Mean", color="red")
    sns.kdeplot(data=df2, x="Pkt Len Mean", color="green")
    plt.legend(labels=["Attack", "Normal"], frameon=False)

    plt.subplot(1, 2, 2)
    sns.kdeplot(data=df1, x="Flow IAT Min", color="red")
    sns.kdeplot(data=df2, x="Flow IAT Min", color="green")
    plt.legend(labels=["Attack", "Normal"], frameon=False)

    # plt.figure(dpi=64)
    # for i in range(1, columns.size):
    #     plt.subplot(4, 4, i)
    #     sns.kdeplot(data=df1, x=columns[i - 1], color="red")
    #     sns.kdeplot(data=df2, x=columns[i - 1], color="green")
    #     plt.legend(labels=["Attack", "Normal"], frameon=False)

    plt.tight_layout()
    plt.savefig("feature.svg", dpi=300, format="svg")
    # plt.show()
