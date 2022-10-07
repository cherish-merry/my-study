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
    df = pd.read_csv("/media/ckz/T7/datasets/CICIDS2017/wednesday/csv/Wednesday-WorkingHours.pcap_Flow.csv",
                     converters={"Label": label})
    df = df.dropna()

    # df = df.drop(df[df['Flow Duration'] == 0].index)

    df = df.drop(['Flow Duration'], axis=1)

    df1 = df.drop(df[df['Label'] == 0].index)

    print(df1.shape)

    df2 = df.drop(df[df['Label'] == 1].index)

    print(df2.shape)

    columns = np.array(df.columns)
    print(columns[0])

    for i in range(0, columns.size):
        sns.kdeplot(data=df1, x=columns[i], color="red")
        sns.kdeplot(data=df2, x=columns[i], color="green")
        plt.legend(labels=["Attack", "Normal"], frameon=False)
        plt.show()
