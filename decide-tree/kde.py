import pandas as pd
import numpy as np
import matplotlib

# matplotlib.use('qtagg')
import matplotlib.pyplot as plt
import seaborn as sns


def label(s):
    if s == "BENIGN":
        return 0
    else:
        return 1


if __name__ == '__main__':
    df = pd.read_csv("dataset/CICIDS-ip-15.csv",
                     converters={"Label": label})

    df[df < 0] = 0

    df1 = df.drop(df[df['Label'] == 1].index)

    print("normal flow:", df1.shape)

    df2 = df.drop(df[df['Label'] == 0].index)

    print("attack flow", df2.shape)

    columns = np.array(df.columns)
    print(columns)

    plt.figure(dpi=300)

    plt.subplot(1, 2, 1)
    sns.kdeplot(data=df1, x="Flow Pkts/s", color="red")
    sns.kdeplot(data=df2, x="Flow Pkts/s", color="green")
    plt.legend(labels=["Attack", "Normal"], frameon=False)

    plt.subplot(1, 2, 2)
    sns.kdeplot(data=df1, x="Pkt Len Mean", color="red")
    sns.kdeplot(data=df2, x="Pkt Len Mean", color="green")
    plt.legend(labels=["Attack", "Normal"], frameon=False)

    # plt.subplot(1, 3, 3)
    # sns.kdeplot(data=df1, x="Flow IAT Max", color="red")
    # sns.kdeplot(data=df2, x="Flow IAT Max", color="green")
    # plt.legend(labels=["Attack", "Normal"], frameon=False)

    # plt.figure(dpi=300)
    # for i in range(1, columns.size - 1):
    #     df3 = df1.drop(df1[df1[columns[i - 1]] == 0].index)
    #     df4 = df2.drop(df2[df2[columns[i - 1]] == 0].index)
    #     plt.subplot(4, 4, i)
    #     sns.kdeplot(data=df3, x=columns[i - 1], color="red")
    #     sns.kdeplot(data=df4, x=columns[i - 1], color="green")
    #     plt.legend(labels=["Attack", "Normal"], frameon=False)
    plt.tight_layout()
    plt.savefig("feature.svg", dpi=300, format="svg")
    plt.show()
