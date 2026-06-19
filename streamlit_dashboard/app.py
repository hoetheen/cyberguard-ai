"""
Day 9
- Attack distribution visualization
- Model results selection
- Selected contamination value
- Dashboard now communicates both data and 
model performance
"""

import streamlit as st
import pandas as pd
df = pd.read_csv("../data/cybersecurity_model.csv")
st.title("CyberGuard AI Dashboard")
st.subheader("Overview")
st.write(f"Total Records: {len(df.index)}")

attackcount = (df["label"] == 1).sum()
st.write(f"Total Attacks: {attackcount}")

benigncount = (df["label"]==0).sum()
st.write(f"Total Benign Records: {benigncount}")

st.subheader("Dataset Preview")
st.dataframe(df.head())



st.subheader("Attack Type Distribution")
attack_type_table = df.value_counts(df["attack_type"])
st.dataframe(attack_type_table)

#display bar chart
attack_type_table = attack_type_table.to_frame()
#st.write(f"{type(attack_type_table)}")
attack_type_table.drop("benign", inplace=True)
#st.dataframe(attack_type_table)
st.bar_chart(attack_type_table)

#Display results
st.subheader("Model Results")
anomalycount = (df["prediction"] == -1).sum()
st.write(f"Number of anomalies detected = {anomalycount}")
st.write(f"Percentage of anomalies detected = {anomalycount / len(df.index) * 100}%")

#Model performance
st.subheader("How well did this model perform?")
anomalies = df[df["prediction"]==-1]
st.write("Confusion Matrix")
st.dataframe(anomalies["label"].value_counts())

st.write("Statistics obtained")
rec_num = (anomalies["label"] == 1).sum()
rec_den = (df["label"] == 1).sum()
st.write(f"Recall: {int(rec_num / rec_den * 100)}%")

#if can change brute force to general code
brute_num = (anomalies["attack_type"] == "brute-force").sum()
brute_den = (df["attack_type"] == "brute-force").sum()
st.write(f"% Brute force attacks detected = {int(brute_num / brute_den * 100)}%")

# streamlit run app.py