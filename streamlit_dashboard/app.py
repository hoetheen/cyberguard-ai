"""
Day 9
- Attack distribution visualization
- Model results selection
- Selected contamination value
- Dashboard now communicates both data and 
model performance
"""
import sys
from pathlib import Path

#Add project root to Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import streamlit as st
import pandas as pd

from config import (
    features,
    contamination,
    n_estimators,
    max_samples,
    algorithm
)

df = pd.read_csv("data/cybersecurity_model.csv")
st.title("CyberGuard AI")
#Project Description
st.write("")

#Dataset preview
st.markdown('<p style="font-size:36px;">Dataset Preview</p>', unsafe_allow_html=True)
st.dataframe(df.head(3))

attackcount = (df["label"] == 1).sum()
benigncount = (df["label"]==0).sum()
number_of_features = len(features)
column_count = df.shape[1]

st.code(f"""+------------+-------------+
| Records     | Attacks    |
| {len(df.index)}        | {attackcount}        |
+------------+-------------+""")

st.code(f"""+------------+-------------+
| Benign     |Features Used|
| {benigncount}       | {number_of_features}/{column_count}        |
+------------+-------------+""")

st.subheader("Attack Type Distribution")
attack_type_table = df.value_counts(df["attack_type"])
st.dataframe(attack_type_table)

#display bar chart
attack_type_table = attack_type_table.to_frame()
attack_type_table.drop("benign", inplace=True)
st.bar_chart(attack_type_table)

st.markdown('<p style="font-size:36px;">Features Used</p>', unsafe_allow_html=True)
for feature in features:
    st.write(f"- {feature}")


#Model Configuration
st.markdown('<p style="font-size:36px;">Model Configuration</p>', unsafe_allow_html=True)
st.write(f"Algorithm Used: {algorithm}")
st.markdown('<p style="font-size:26px;">Parameters</p>', unsafe_allow_html=True)
st.write(f"Contamination = {contamination}")
st.write(f"n_estimators = {n_estimators}")
st.write(f"max_samples = {max_samples}")


#Display results
st.subheader("Model Results")
anomalycount = (df["prediction"] == -1).sum()
st.write(f"Number of anomalies detected = {anomalycount}")
st.write(f"Percentage of anomalies detected = {anomalycount / len(df.index) * 100}%")

#Model performance
st.subheader("Model Performance")
anomalies = df[df["prediction"]==-1]

true_positive = (anomalies["label"] == 1).sum()
false_positive = (anomalies["label"] == 0).sum()

true_negative = benigncount - false_positive
false_negative = attackcount - true_positive

confusion_data = [[true_negative, false_positive], [false_negative, true_positive]]
st.write("Confusion Matrix")
confusion_table = pd.DataFrame(confusion_data,
                               index=['Actual Benign', 'Attack'],
                               columns=['Benign', 'Attack'])
st.dataframe(confusion_table)

#Calculating Precision and Accuracy
precision = int(true_positive / anomalycount * 100)
accuracy = int((true_positive + true_negative) / len(df.index) * 100)

#Calculating %Brute Force Attacks
brute_num = (anomalies["attack_type"] == "brute-force").sum()
brute_den = (df["attack_type"] == "brute-force").sum()

stats_data = [f"{int(true_positive / attackcount * 100)}%", f"{precision}%", f"{accuracy}%", f"{int(brute_num / brute_den * 100)}%"]
stats_table = pd.DataFrame(stats_data,
                           index=["Recall", "Precision", 
                                  "Accuracy", 
                                  "% Brute Force Attacks Detected"],
                           columns=["Percentage"])
st.dataframe(stats_table)

#Conclusion
st.subheader("Key Takeaways")
st.write("")


# streamlit run streamlit_dashboard/app.py