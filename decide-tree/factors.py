import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV
from scipy.stats import randint as sp_randint
from utils import binary_process

columns, x, y = binary_process(None, 100)

# 定义参数空间
param_dist = {"n_estimators": sp_randint(1, 63),
              "max_depth": sp_randint(2, 32),
              "max_leaf_nodes": sp_randint(16, 512)}

# 使用RandomizedSearchCV进行随机搜索
clf = RandomForestClassifier()
random_search = RandomizedSearchCV(clf, param_distributions=param_dist, n_iter=64, cv=5, scoring='accuracy')
random_search.fit(x, y)

# 输出最佳参数和最佳得分
print("Best parameters:", random_search.best_params_)
print("Best score:", random_search.best_score_)

# 可视化为3D图表
results = random_search.cv_results_
fig = plt.figure(figsize=(8, 8), dpi=300)
ax = fig.add_subplot(111, projection='3d')
sc = ax.scatter(results['param_n_estimators'], results['param_max_depth'], results['param_max_leaf_nodes'],
                c=results['rank_test_score'], cmap='Spectral', s=100, alpha=0.8, edgecolors='none')
ax.set_xlabel('n_estimators', fontsize=14, labelpad=8)
ax.set_ylabel('max_depth', fontsize=14, labelpad=8)
ax.set_zlabel('max_leaf_nodes', fontsize=14, labelpad=8)
ax.tick_params(axis='x', labelsize=12, pad=4)
ax.tick_params(axis='y', labelsize=12, pad=4)
ax.tick_params(axis='z', labelsize=12, pad=4)
ax.xaxis.pane.fill = False
ax.xaxis.grid(True, which='major', linestyle='-', linewidth=0.5, color='gray', alpha=0.5)
ax.yaxis.pane.fill = False
ax.yaxis.grid(True, which='major', linestyle='-', linewidth=0.5, color='gray', alpha=0.5)
ax.zaxis.pane.fill = False
ax.zaxis.grid(True, which='major', linestyle='-', linewidth=0.5, color='gray', alpha=0.5)
ax.view_init(elev=20, azim=120)
fig.colorbar(sc, label='Rank Test Score', shrink=0.5, aspect=10, pad=0, orientation='horizontal')
plt.tight_layout()
plt.savefig("img/factors.svg", dpi=300, format="svg")
plt.show()
