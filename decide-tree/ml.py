import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score, roc_auc_score
from sklearn.metrics import log_loss
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
import matplotlib.pyplot as plt


def label(s):
    if s == "BENIGN":
        return 0
    else:
        return 1


def print_score(pred, test):
    print("accuracy_score:", accuracy_score(pred, test))
    print("precision_score:", precision_score(pred, test))
    print("recall_score:", recall_score(pred, test))
    print("f1_score:", f1_score(pred, test))
    print("log_loss:", log_loss(pred, test))
    print("roc_auc_score:", roc_auc_score(pred, test))


df = pd.read_csv("dataset/CICIDS-ip-15.csv",
                 converters={"Label": label})

df[df < 0] = 0

train_data = df.sample(frac=0.6, random_state=0, axis=0)
test_data = df[~df.index.isin(train_data.index)].sample(frac=1, random_state=0, axis=0)
train_array = np.array(train_data)

train_array[np.isinf(train_array)] = 0

train_x = train_array[:, :train_array.shape[1] - 1]
train_y = train_array[:, train_array.shape[1] - 1]

test_array = np.array(test_data)
test_array[np.isinf(test_array)] = 0
test_x = test_array[:, :test_array.shape[1] - 1]
test_y = test_array[:, test_array.shape[1] - 1]
exceptions = train_data.Label.value_counts().values[1]

max_depth = 8
max_leaf_nodes = 64

# decide tree
dt = DecisionTreeClassifier()
dt.fit(train_x, train_y)
dt_pred = dt.predict(test_x)
print("decide tree:")
print_score(dt_pred, test_y)
print("-----------------------------------")

# random forest
rf = RandomForestClassifier()
rf.fit(train_x, train_y)
rf_pred = rf.predict(test_x)
print("random forest:")
print_score(rf_pred, test_y)
print("-----------------------------------")

# test = []
# for i in range(100):
#     rf2 = RandomForestClassifier(max_depth=max_depth, max_leaf_nodes=max_leaf_nodes, n_estimators=i + 1)
#     rf2.fit(train_x, train_y)
#     rf2_pred = rf2.predict(test_x)
#     test.append(log_loss(rf2_pred, test_y))
# plt.plot(range(1, 101), test, color="red", label="tree num")
# plt.legend()
# plt.show()

# knn
knn = KNeighborsClassifier()
knn.fit(train_x, train_y)
knn_pred = knn.predict(test_x)
print("knn:")
print_score(knn_pred, test_y)
print("-----------------------------------")

# svm
svm = SVC()
svm.fit(train_x, train_y)
svm_pred = svm.predict(test_x)
print("svm:")
print_score(svm_pred, test_y)
print("-----------------------------------")

# naive_bayes
nb = MultinomialNB()
nb.fit(train_x, train_y)
nb_pred = nb.predict(test_x)
print("nb:")
print_score(nb_pred, test_y)
print("-----------------------------------")

# LR
lr = LogisticRegression(max_iter=1000)
lr.fit(train_x, train_y)
lr_pred = lr.predict(test_x)
print("lr:")
print_score(lr_pred, test_y)
print("-----------------------------------")
