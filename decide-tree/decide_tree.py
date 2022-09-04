import pandas as pd
import numpy as np
from sklearn import tree
import graphviz
from bcc.utils import printb

# [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 43, 44]
# Dos GoldenEye Packet Len Std、Flow IAT Min、Flow IAT Mean、Fwd IAT Min
#

'''
duration packetNum
minPacketLength maxPacketLength meanPacketLength totalPacketLength
minIAT maxIAT meanIAT  totalIAT
minActiveTime maxActiveTime

1 2 
7 6 8 4
19 18 16 20
73 72 70 

0 ' Destination Port'  +
1 ' Flow Duration' +
2 ' Total Fwd Packets' +
3 ' Total Backward Packets' +
4 'Total Length of Fwd Packets' +
5 ' Total Length of Bwd Packets' +
6 ' Fwd Packet Length Max' +
7 ' Fwd Packet Length Min' +
8 ' Fwd Packet Length Mean' +
9 ' Fwd Packet Length Std' +
10 'Bwd Packet Length Max' +
11 ' Bwd Packet Length Min' +
12 ' Bwd Packet Length Mean' +
13 ' Bwd Packet Length Std' +
14 'Flow Bytes/s'
15 ' Flow Packets/s' 
16 ' Flow IAT Mean' +
17 ' Flow IAT Std' +
18 ' Flow IAT Max' +
19 ' Flow IAT Min' +
20 'Fwd IAT Total' 
21 ' Fwd IAT Mean' 
22 ' Fwd IAT Std'
23 ' Fwd IAT Max' 
24 ' Fwd IAT Min' 
25 'Bwd IAT Total' 
26 ' Bwd IAT Mean'
27 ' Bwd IAT Std' 
28 ' Bwd IAT Max' 
29 ' Bwd IAT Min' 
30 'Fwd PSH Flags'
31 ' Bwd PSH Flags' 
32 ' Fwd URG Flags' 
33 ' Bwd URG Flags' 
34 ' Fwd Header Length'
35 ' Bwd Header Length' 
36 'Fwd Packets/s' 
37 ' Bwd Packets/s'
38 ' Min Packet Length'     np.savetxt("./childrenLeft.txt", clf.tree_.children_left, fmt='%d')
    np.savetxt("./childrenRight.txt", clf.tree_.children_right, fmt='%d')

    np.savetxt("./feature.txt", clf.tree_.feature, fmt='%d')
    np.savetxt("./threshold.txt", clf.tree_.threshold, fmt='%d')
    np.savetxt("./value.txt", clf.tree_.value, fmt='%d')
39 ' Max Packet Length' 
40 ' Packet Length Mean'
41 ' Packet Length Std' 
42 ' Packet Length Variance' 
43 'FIN Flag Count' +
44 ' SYN Flag Count'  +
45 ' RST Flag Count' 
46 ' PSH Flag Count' 
47 ' ACK Flag Count'
48 ' URG Flag Count' 
49 ' CWE Flag Count' 
50 ' ECE Flag Count' 
51 ' Down/Up Ratio'
52 ' Average Packet Size' 
53 ' Avg Fwd Segment Size' 
54 ' Avg Bwd Segment Size'
55 ' Fwd Header Length.1' 
56 'Fwd Avg Bytes/Bulk' 
57 ' Fwd Avg Packets/Bulk'
58 ' Fwd Avg Bulk Rate' 
59 ' Bwd Avg Bytes/Bulk' 
60 ' Bwd Avg Packets/Bulk'
61 'Bwd Avg Bulk Rate' 
62 'Subflow Fwd Packets' 
63 ' Subflow Fwd Bytes'
64 ' Subflow Bwd Packets' 
65 ' Subflow Bwd Bytes' 
66 'Init_Win_bytes_forward'
67 ' Init_Win_bytes_backward' 
68 ' act_data_pkt_fwd' 
69 ' min_seg_size_forward'
70 'Active Mean' 
71 ' Active Std' 
72 ' Active Max' 
73 ' Active Min' 
74 'Idle Mean'
75 ' Idle Std' 
76 ' Idle Max' 
77 ' Idle Min' 
78 ' Label']
'''

'''

Bwd Packet Length Std
Packet Length Mean
'''


def label(s):
    if s == "BENIGN":
        return 0
    else:
        return 1


if __name__ == '__main__':
    np.set_printoptions(threshold=np.inf)
    pd.set_option('display.max_columns', None)  # 显示完整的列
    pd.set_option('display.max_rows', None)  # 显示完整的行

    data = pd.read_csv("Wednesday-workingHours.pcap_ISCX.csv"
                       , converters={" Label": label}, usecols=
                       [1, 2, 7, 6, 8, 4, 19, 18, 16, 20, 73, 72, 70, 78])

    columns = np.array(data.columns)

    print(columns)

    array = np.array(data)

    array[np.isnan(array)] = 0

    array[np.isinf(array)] = 0

    x = array[:, :array.shape[1] - 1]
    y = array[:, array.shape[1] - 1]

    print(x.shape)

    class_names = ["Normal", "Exception"]

    clf = tree.DecisionTreeClassifier(max_depth=10, max_leaf_nodes=100)
    clf = clf.fit(x, y)

    np.savetxt("./result/childrenLeft", clf.tree_.children_left, fmt='%d')
    np.savetxt("./result/childrenRight", clf.tree_.children_right, fmt='%d')

    np.savetxt("./result/feature", clf.tree_.feature, fmt='%d')
    np.savetxt("./result/threshold", clf.tree_.threshold, fmt='%d')

    values = clf.tree_.value
    value = []
    for val in values:
        value.append(np.argmax(val))
    np.savetxt("./result/value", np.array(value), fmt='%d')

    dot_data = tree.export_graphviz(clf, out_file=None,
                                    feature_names=columns[:columns.shape[0] - 1],
                                    class_names=class_names,
                                    filled=True, rounded=True,
                                    special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render("./result/decide_tree")
