import pickle
import pandas as pd
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from utils.preprocessor import clean_text

BASE_DIR  = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / 'data' / 'phishing_dataset.csv'

print("Loading dataset...")

# Auto-detect separator
for sep in [',', ';', '\t']:
    try:
        df = pd.read_csv(DATA_PATH, encoding='latin-1', sep=sep)
        if df.shape[1] > 1:
            print(f"Separator detected: '{sep}'")
            break
    except:
        continue

print("Columns found:", df.columns.tolist())
print("Shape:", df.shape)

# ── Auto-detect text and label columns ───────────────────────────────────────
cols = df.columns.tolist()

text_col  = 'Email Text'
label_col = 'Email Type'

if not text_col or not label_col:
    print("\nCould not auto-detect columns. Columns available:")
    for c in cols:
        print(f"  '{c}' — unique values: {df[c].nunique()}, sample: {df[c].iloc[0][:80] if df[c].dtype==object else df[c].iloc[0]}")
    exit()

print(f"\nText column  : '{text_col}'")
print(f"Label column : '{label_col}'")
print("Label values :", df[label_col].unique())

df = df[[text_col, label_col]].dropna()
print(f"Rows: {len(df)}")

# Convert labels to 0 and 1 if they are text like 'Phishing Email' / 'Safe Email'
if df[label_col].dtype == object:
    unique_labels = df[label_col].unique()
    print(f"Converting labels: {unique_labels}")
    # Phishing = 1, Legitimate/Safe = 0
    phishing_keywords = ['phish', 'spam', 'malicious', 'fraud']
    def label_to_int(val):
        val_lower = str(val).lower()
        for kw in phishing_keywords:
            if kw in val_lower:
                return 1
        return 0
    df['label_int'] = df[label_col].apply(label_to_int)
    label_col = 'label_int'

print("Label distribution:\n", df[label_col].value_counts())

print("\nCleaning text (1-2 minutes)...")
df['clean'] = df[text_col].apply(clean_text)

X = df['clean']
y = df[label_col]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train: {len(X_train)}  |  Test: {len(X_test)}")

print("Vectorizing...")
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)

print("Training model (1-2 minutes)...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train_vec, y_train)

y_pred = model.predict(X_test_vec)
print(f"\nAccuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=['Legitimate','Phishing']))

models_dir = BASE_DIR / 'models'
models_dir.mkdir(exist_ok=True)
with open(models_dir / 'phishing_model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open(models_dir / 'vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

print("\n✅ Model saved successfully!")