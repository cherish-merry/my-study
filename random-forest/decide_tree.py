from sklearn import tree
from utils import process_data, print_score, export_tree

if __name__ == '__main__':
    dt = tree.DecisionTreeClassifier(max_depth=12, min_impurity_decrease=0.0001)
    columns, train_x, test_x, train_y, test_y = process_data()
    dt = dt.fit(train_x, train_y)
    export_tree(dt, columns)
    # predict
    predict_y = dt.predict(test_x)
    print_score(predict_y, test_y)
