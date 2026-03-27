import pandas as pd
from sklearn.datasets import load_breast_cancer

def load_data_from_csv(filepath):
    """Loads dataset from a CSV file."""
    return pd.read_csv(filepath)

def load_data_from_sklearn():
    """Loads dataset from sklearn and returns it as a DataFrame."""
    cancer = load_breast_cancer()
    df_cancer = pd.DataFrame(cancer.data, columns=cancer.feature_names)
    df_cancer['target'] = cancer.target
    return df_cancer, cancer.target_names
