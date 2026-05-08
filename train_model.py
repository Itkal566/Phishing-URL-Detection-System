import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle
from features import extract_features

data = pd.read_csv("url_phishing_dataset_5000.csv")

X = []
y = []

for i in range(len(data)):
    
    url = data["url"][i]
    label = data["label"][i]

    features = extract_features(url)

    X.append(features)
    y.append(label)

model = RandomForestClassifier(n_estimators=200)

model.fit(X, y)

pickle.dump(model, open("model.pkl","wb"))

print("Model trained successfully")