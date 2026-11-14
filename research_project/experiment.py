# Machine Learning Experiment Tracker
import math

def calculate_metrics(data_points):
    print("Processing confidential experiment results...")
    return sum(data_points) / len(data_points)

if __name__ == "__main__":
    scores = [98.5, 94.2, 99.1, 91.0]
    print(f"Average accuracy: {calculate_metrics(scores):.2f}%")
