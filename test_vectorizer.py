import pickle

print("Checking backend/app/models/vectorizer.pkl")

with open("app/models/vectorizer.pkl", "rb") as f:
    v = pickle.load(f)

print("Has vocabulary:", hasattr(v, "vocabulary_"))
print("Has idf:", hasattr(v, "idf_"))

if hasattr(v, "vocabulary_"):
    print("Vocab size:", len(v.vocabulary_))