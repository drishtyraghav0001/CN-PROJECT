# FlowWatch — Network Traffic Monitoring and Anomaly Detection

## About
FlowWatch is a Python-based network traffic monitoring project that analyzes network traffic data and identifies potentially unusual activity using statistical techniques and machine learning.

## Features
- Upload network traffic data in CSV or JSON format.
- Analyze network traffic records and protocols.
- Detect potential anomalies using statistical analysis.
- Use the Isolation Forest machine learning algorithm to identify unusual traffic patterns.
- Visualize traffic analysis results using an interactive dashboard.
- View and download anomaly reports.

## Technologies Used
- Python
- Streamlit
- Pandas
- Scikit-learn
- Plotly

## How to Run

1. Clone or download this repository.
2. Install the required Python libraries.
3. Run the dashboard:

```bash
python -m streamlit run model_dashboard.py
```

4. Open the local URL displayed in the terminal.

## Note
The included traffic datasets are for testing and demonstration. An anomaly flagged by the model is not necessarily a confirmed cyberattack.

## Future Improvements
- Analyze live network traffic.
- Add more network traffic features.
- Evaluate detection accuracy using labeled datasets.
- Improve anomaly alerts and reporting.
