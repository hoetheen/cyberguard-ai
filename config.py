features = ["protocol", "is_internal_traffic", 
            "src_port", "dst_port",
            "bytes_sent", "bytes_received"]

contamination = 0.5
n_estimators = 100
max_samples = 256

algorithm = "Isolation Forest"