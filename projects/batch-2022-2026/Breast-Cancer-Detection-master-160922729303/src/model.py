from sklearn.svm import SVC
from sklearn.model_selection import GridSearchCV

def get_optimized_svc(X_train, y_train):
    """Uses GridSearchCV to find and return the best SVC model."""
    param_grid = {
        'C': [0.1, 1, 10, 100], 
        'gamma': [1, 0.1, 0.01, 0.001], 
        'kernel': ['rbf']
    }
    
    grid = GridSearchCV(SVC(), param_grid, refit=True, verbose=0)
    grid.fit(X_train, y_train)
    return grid.best_estimator_, grid.best_params_

def build_svc(C=10, gamma=0.1, kernel='rbf'):
    """Returns a basic SVC model with specified parameters."""
    return SVC(C=C, gamma=gamma, kernel=kernel)
