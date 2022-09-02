from sklearn import tree
from sklearn.datasets import load_iris
import graphviz


def demo01():
    x = [[0, 0], [1, 1]]
    y = [0, 1]
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(x, y)
    print(clf.predict([[2., 2.]]))
    print(clf.predict_proba([[2., 2.]]))


def demo02():
    iris = load_iris()
    clf = tree.DecisionTreeClassifier()

    clf = clf.fit(iris.data, iris.target)
    # dot_data = tree.export_graphviz(clf, out_file=None,
    #                                 feature_names=iris.feature_names,
    #                                 class_names=iris.target_names,
    #                                 filled=True, rounded=True,
    #                                 special_characters=True)
    # graph = graphviz.Source(dot_data)
    # graph.render("iris")

    r = tree.export_text(clf, feature_names=iris.feature_names)
    print(r)


if __name__ == '__main__':
    demo02()
