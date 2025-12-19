import pandas as pd
import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

def load_and_standardize(filename, attack_type):
    try:
        df = pd.read_csv(filename, encoding='utf-8')
    except:
        df = pd.read_csv(filename, encoding='latin-1')
    
    cols = [c.lower() for c in df.columns]
    if 'sentence' in cols: df = df.rename(columns={df.columns[cols.index('sentence')]: 'payload'})
    elif 'query' in cols: df = df.rename(columns={df.columns[cols.index('query')]: 'payload'})
    elif 'text' in cols: df = df.rename(columns={df.columns[cols.index('text')]: 'payload'})
    if 'label' in cols: df = df.rename(columns={df.columns[cols.index('label')]: 'label'})

    df['label'] = pd.to_numeric(df['label'], errors='coerce')
    df = df.dropna(subset=['label'])
    df['type'] = df['label'].map({1: attack_type, 0: 'Normal'})
    df = df.dropna(subset=['type'])
    return df[['payload', 'type']]

def generate_synthetic_data():
    cmdi = ["; ls -la", "| cat /etc/passwd", "&& whoami", "| nc -l -p 8080", "ping -c 4 127.0.0.1"] * 100
    lfi = ["../../../../etc/passwd", "../boot.ini", "..\\windows\\win.ini", "/proc/self/environ"] * 100
    rce = ["import os; os.system('id')", "eval(base64_decode('...'))", "system('cat /etc/passwd')"] * 100
    return pd.concat([pd.DataFrame({'payload': cmdi, 'type': 'Cmdi'}), pd.DataFrame({'payload': lfi, 'type': 'LFI'}), pd.DataFrame({'payload': rce, 'type': 'RCE'})])

def train_brain():
    print("Loading Data...")
    df_sql = load_and_standardize("sql_dataset.csv", "SQLi")
    df_xss = load_and_standardize("XSS_dataset.csv", "XSS")
    if df_sql is None or df_xss is None: return

    df = pd.concat([df_sql, df_xss, generate_synthetic_data()]).dropna(subset=['payload'])
    df['payload'] = df['payload'].astype(str)
    
    X_train, X_test, y_train, y_test = train_test_split(df['payload'], df['type'], test_size=0.2, random_state=42)
    pipeline = make_pipeline(TfidfVectorizer(analyzer='char', ngram_range=(1, 4)), RandomForestClassifier(n_estimators=100))
    pipeline.fit(X_train, y_train)

    print(f"Accuracy: {accuracy_score(y_test, pipeline.predict(X_test)) * 100:.2f}%")
    if not os.path.exists("app"): os.makedirs("app")
    joblib.dump(pipeline, "app/model.pkl")
    print("Model Saved.")

if __name__ == "__main__":
    train_brain()