from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from utils import process_data, print_score

columns, train_x, test_x, train_y, test_y = process_data()

# decide tree
dt = DecisionTreeClassifier()
dt.fit(train_x, train_y)
dt_pred = dt.predict(test_x)
print("decide tree:")
print_score(dt_pred, test_y)
print("-----------------------------------")

# random forest
rf = RandomForestClassifier(n_estimators=11)
rf.fit(train_x, train_y)
rf_pred = rf.predict(test_x)
print("random forest:")
print_score(rf_pred, test_y)
print("-----------------------------------")

# knn
knn = KNeighborsClassifier()
knn.fit(train_x, train_y)
knn_pred = knn.predict(test_x)
print("knn:")
print_score(knn_pred, test_y)
print("-----------------------------------")

# naive_bayes
nb = MultinomialNB()
nb.fit(train_x, train_y)
nb_pred = nb.predict(test_x)
print("nb:")
print_score(nb_pred, test_y)
print("-----------------------------------")

# LR
lr = LogisticRegression(max_iter=10000)
lr.fit(train_x, train_y)
lr_pred = lr.predict(test_x)
print("lr:")
print_score(lr_pred, test_y)
print("-----------------------------------")
