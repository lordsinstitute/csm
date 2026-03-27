import joblib
import os
from src.loader import load_data_from_sklearn
from src.preprocessor import split_data, Preprocessor
from src.model import get_optimized_svc
from sklearn.metrics import classification_report, accuracy_score

def train_pipeline():
    print("Loading data...")
    df, target_names = load_data_from_sklearn()
    X = df.drop(['target'], axis=1)
    y = df['target']

    print("Splitting data...")
    X_train, X_test, y_train, y_test = split_data(X, y)

    print("Preprocessing (Scaling)...")
    preprocessor = Preprocessor()
    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)

    print("Tuning and training SVC model (this may take a few seconds)...")
    model, params = get_optimized_svc(X_train_scaled, y_train)
    print(f"Best Params: {params}")

    print("Evaluating model...")
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=target_names))

    print("Saving artifacts...")
    joblib.dump(model, 'model.pkl')
    joblib.dump(preprocessor, 'scaler.pkl')
    print("Done! model.pkl and scaler.pkl created.")

if __name__ == "__main__":
    train_pipeline()
