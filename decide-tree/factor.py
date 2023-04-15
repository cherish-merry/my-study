from sklearn.model_selection import cross_val_score, cross_val_predict
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import numpy as np
from scipy.interpolate import make_interp_spline
from utils import binary_process
import time

columns, x, y = binary_process(None, 100)

fig, axs = plt.subplots(nrows=1, ncols=3, figsize=(18, 6), dpi=300)

n_estimators_list = np.linspace(1, 63, num=32, dtype=int)

max_depths = np.linspace(2, 32, num=31, dtype=int)

max_leaf_nodes = np.linspace(16, 512, num=32, dtype=int)


def evaluate(name, intervals, ax, indicator, x_label, y_label):
    accuracies = []
    log_losses = []
    run_times = []
    for interval in intervals:
        start_time = time.time()
        rf = RandomForestClassifier(n_estimators=interval, random_state=42)
        accuracy_scores = cross_val_score(rf, x, y, cv=5, scoring=indicator)
        accuracies.append(np.mean(accuracy_scores))
        log_loss_scores = -1.0 * cross_val_predict(rf, x, y, cv=5, method='predict', n_jobs=-1, verbose=0)
        log_losses.append(np.mean(log_loss_scores))
        run_time = time.time() - start_time
        run_times.append(run_time)
        print(
            f"{name}={interval}: Accuracy={np.mean(accuracy_scores):.3f}, Log Loss={np.mean(log_loss_scores):.3f}, Time={run_time:.3f} seconds")
    color = 'tab:red'
    ax.set_xlabel(name)
    if x_label:
        ax.set_ylabel("Accuracy", color=color)
    x_new = np.linspace(intervals.min(), intervals.max(), 300)
    spl = make_interp_spline(intervals, accuracies, k=3)
    y_new = spl(x_new)
    ax.plot(x_new, y_new, color=color)
    ax.tick_params(axis='y', labelcolor=color)
    ax_twin = ax.twinx()
    color = 'tab:blue'
    if y_label:
        ax_twin.set_ylabel('Log Loss', color=color)
    spl = make_interp_spline(intervals, log_losses, k=3)
    y_new = spl(x_new)
    ax_twin.plot(x_new, y_new, color=color)
    ax_twin.tick_params(axis='y', labelcolor=color)
    fig.subplots_adjust(wspace=0.5)
    return run_times


n_tree_times = evaluate("Number of Trees", n_estimators_list, axs[0], "accuracy", True, False)
max_depth_times = evaluate("Max Depth", max_depths, axs[1], "accuracy", False, False)
max_leaf_nodes_times = evaluate("Max Leaf Nodes", max_leaf_nodes, axs[2], "accuracy", False, True)

plt.savefig("img/factor.svg", dpi=300, format="svg")
plt.show()

print("Average run time for Number of Trees:", np.mean(n_tree_times))
print("Average run time for Max Depth:", np.mean(max_depth_times))
print("Average run time for Max Leaf Nodes:", np.mean(max_leaf_nodes_times))
