Cyberguard AI

Contents
1. Project Overview
2. Dataset
3. Stage 1: Data Preparation
4. Stage 2: Machine Learning
5. Stage 3: Dashboard Development
6. Results
7. Limitations
8. Future Improvements

Project Overview
Recent cybersecurity attacks pose an even greater threat to the society than before, and it is difficult for us to detect and prevent these attacks from happening without the help of technology.

This program consists of an anomaly detection model trains from previous attacks, and learns its features and properties. This allows it to better predict future attacks through feature recognition. 

This system would benefit small businesses that aim to boost fraud prevention and reduce cyberattacks.

Technologies used
- Python
- Pandas
- Jupyter
- Scikit-learn
- Streamlit
- Github

Skills involved
- Data Cleaning
- Feature Engineering
- Model Evaluation
- Machine Learning
- Dashboard Development
- Trade-off Analysis

The project has successfully demonstrated its capability not only to flag suspicious network traffic, but also to compile findings into a cybersecurity dashboard for better comparability.

Dataset
Name: Cybersecurity Threat Detection Dataset
Link to original data: https://www.kaggle.com/datasets/dhrubangtalukdar/cybersecurity-threat-detection-dataset?select=cybersecurity.csv

Each row represents a network connection, with a total of 10 000 records and 13 features. 

Label - Takes either 0 or 1, 0 represents benign, 1 represents malign
Attack_type - Type of attack, output values include: brute-force, port-scan, sql-injection etc.

The first reason is that there are attributes e.g. bytes_sent, bytes_received which provides useful information into whether or not a connection is a cyberattack.
The second reason is that this dataset contains the "Label" column. This makes it more viable to build a model that trains on existing data, because metrics e.g. accuracy can be evaluated using the "Label" column.

Stage 1: Data Preparation

Data Cleaning
There were records with empty values for the "url" column, so I decided to remove all these records from the dataset. 

The cleaned dataset had only 6768 records instead of the original 10 000, and even though there is a drop of 32.3% of data from the dataset, I decided that 6768 records was more than enough to train a working model.


Feature Engineering
I decided early on to use machine learning to tackle this project, which means the attributes that I want to pass into the model have to contain values of type integer. I made the changes to the following columns:
- "protocol"
- "is_internal_traffic"
- "src_ip"
- "dst_ip"
and more.

This is the first trial of the model. So I have added only the following attributes to the model:
- "protocol"
- "is_internal_traffic"
- "src_port"
- "dst_port"
- "bytes_sent"
- "bytes_received"

All attributes I felt were equally important, however I felt that these 6 attributes combined carried the most information, which would mean that model findings were more interpretable even without adding any more attributes.

Stage 2: Machine Learning

Why Isolation Forest?
This was an anomaly detection project, and so I needed a machine learning algorithm typically suitable for anomaly detection. I found Isolation Forest to be quite applicable to my project, as well as it keeps the program simple while producing concise findings. 

Why contamination? Why prioritize recall?
Compared to the other features in Isolation Forest, contamination was the parameter that influenced the results the most. 
Recall represents the true positive rate of the test. In other words, increasing recall increases the proportion of attacks that get detected by the system, which I felt in my project would make a better model.


Stage 3: Dashboard Development
To present my project, I thought of building a dashboard documenting my findings and results. 
Why Streamlit?

The dashboard provides the dataset overview, but more importantly shows the attack distribution and model performance.
The bar chart illustrates the skewness of the dataset's attack distribution. This shows out of all the attacks, which ones are more prevalent and require more attention to.

Initially the attack distribution chart was meant to contain the number of benign records as well. However this number(6499) is much larger than the number of attacks for each type, and it will skew the bar chart visualization making it uninterpretable. Removing it enabled the tallest bar in the chart to represent the most common attack type, which is what we want to know.

Results
For this trial of the model, I have selected the following parameters
- contamination = 0.5
- n_estimators = 100
- max_samples = 256

How well did the model perform?
Recall = 49.07%
Precision = 3.90%
% Brute Force Attacks Detected = 37.33%

I found out that the model best detected attacks of type ddos, and struggles with attacks e.g. brute force, sql injection.
Prioritizing recall meant that the model increased its frequency of flagging suspicious connections, even though they might just be false alarms. This was what I intended to achieve.

The project was successful because I was able to create the confusion matrix, and the statistics that I found could be interpreted into solving the project problem.


Limitations
As for the purposes of a project, this dataset consists of a large enough number of 10 000 to be analyzed, but I also understand that in real life scenarios, training a model requires millions and maybe even billions of attack data. 

This model is only limited to analyzing CSV data, and it does assume similar future traffic. 


Improvements
If I could work on this project for another 6 months, I would definitely use another algorithm instead of Isolation Forest. As of now while I felt that the model training was successful, I was not satisfied with the results, especially the low recall rate. I hope that my model would achieve a better performance with a different algorithm.

Another improvement could be to adapt the project so that it can detect real-world traffic, providing real-time statistics. That would make it more useful and business applicable.