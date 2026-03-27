import pandas as pd
from sklearn.model_selection import train_test_split

class Preprocessor:
    def __init__(self):
        self.min_vals = None
        self.range_vals = None

    def fit(self, X):
        """Calculates min and range for scaling."""
        self.min_vals = X.min()
        self.range_vals = (X - self.min_vals).max()
        # Handle division by zero if all values are same
        self.range_vals.replace(0, 1, inplace=True)

    def transform(self, X):
        """Applies min-max scaling."""
        if self.min_vals is None or self.range_vals is None:
            raise ValueError("Preprocessor not fitted.")
        return (X - self.min_vals) / self.range_vals

    def fit_transform(self, X):
        self.fit(X)
        return self.transform(X)

def split_data(X, y, test_size=0.2, random_state=5):
    """Splits data into train and test sets."""
    return train_test_split(X, y, test_size=test_size, random_state=random_state)
