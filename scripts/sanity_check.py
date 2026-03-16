import pandas as pd
import sys

csv_path = sys.argv[1]

df = pd.read_csv(csv_path, low_memory=False)

print("Rows:", len(df))
print("Columns:", len(df.columns))

print("\nPort distribution:")
print(df["port"].value_counts())

print("\nLabel success:")
print(df["label_success"].value_counts())

print("\nISP distribution:")
if "src_isp" in df.columns:
    print(df["src_isp"].value_counts())

print("\nField completion:")

for col in df.columns:
    non_null = df[col].notna().sum()
    pct = round(non_null / len(df) * 100, 2)
    print(f"{col}: {pct}%")
