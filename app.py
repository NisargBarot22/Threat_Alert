# Import necessary libraries
from fastapi import FastAPI, UploadFile
from fastapi.responses import JSONResponse
import joblib
import os
from tempfile import NamedTemporaryFile
import json
# from sklearn.preprocessing import LabelEncoder
import scapy.all as scapy
import pandas as pd
import sklearn
from fastapi.middleware.cors import CORSMiddleware

# Create a FastAPI app
app = FastAPI()

origin = [
    "http://localhost",
    "http://localhost:3000"
]
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load your saved model
model = joblib.load("IDS_ID3_model (2).joblib")

tcp_flags_mapping = {
    'A': 1,   # ACK
    'P': 2,   # PSH
    'R': 4,   # RST
    'S': 8,   # SYN
    'F': 16,  # FIN
}
def convert_flags_to_int(flags_str):
    flag_value = 0
    for flag in flags_str:
        if flag in tcp_flags_mapping:
            flag_value |= tcp_flags_mapping[flag]
    return flag_value

def string_to_product(input_string):
    components = input_string.split(".")
    result = 1
    for component in components:
        result *= int(component)
    return result

# Define a function to extract features from a PCAP file
def extract_features_from_pcap(pcap_file):
    # Open the PCAP file for reading
    packets = scapy.rdpcap(pcap_file)

    # Initialize lists to store extracted features
    features = []

    # Iterate through each packet in the PCAP file
    for packet in packets:
        # Check if the packet has an IP layer (IPv4 or IPv6)
        if packet.haslayer(scapy.IP):
            ipv4_src_addr = str(packet[scapy.IP].src)
            ipv4_dst_addr = str(packet[scapy.IP].dst)
            protocol = packet[scapy.IP].proto

            # Check if the packet has a TCP layer
            if packet.haslayer(scapy.TCP):
                l4_src_port = packet[scapy.TCP].sport
                l4_dst_port = packet[scapy.TCP].dport
                tcp_flags = packet[scapy.TCP].flags
            else:
                l4_src_port = ""
                l4_dst_port = ""
                tcp_flags = ""

            # Calculate flow duration (time between the first and last packet in the flow)
            flow_duration = packet.time - packets[0].time

            # Append the extracted features to the list
            features.append([ipv4_src_addr, l4_src_port, ipv4_dst_addr, l4_dst_port, protocol, tcp_flags, int(flow_duration)])

    return features

# Define a route to accept PCAP files and return labels
@app.post("/predict/")
async def predict_pcap(file: UploadFile):
    try:
        # Save the uploaded file to a temporary location
        with NamedTemporaryFile(delete=False) as temp_pcap:
            pcap_data = file.file.read()
            temp_pcap.write(pcap_data)

        # Extract features from the uploaded PCAP file
        features = extract_features_from_pcap(temp_pcap.name)

        for i, feature_vector in enumerate(features):
            features[i] = [str(val) if idx != 6 else str(int(val)) for idx, val in enumerate(feature_vector)]

        # You can process the extracted features here, if needed
        # For example, convert them into a pandas DataFrame
        column_names = [
            'IPV4_SRC_ADDR',
            'L4_SRC_PORT',
            'IPV4_DST_ADDR',
            'L4_DST_PORT',
            'PROTOCOL',
            'TCP_FLAGS',
            'FLOW_DURATION_MILLISECONDS',
        ]

        df = pd.DataFrame(features, columns=column_names)

        df['IPV4_SRC_ADDR'] = df['IPV4_SRC_ADDR'].apply(string_to_product)
        df['IPV4_DST_ADDR'] = df['IPV4_DST_ADDR'].apply(string_to_product)
        df['L4_DST_PORT'] = df['L4_DST_PORT'].astype(str)
        df['L4_SRC_PORT'] = df['L4_SRC_PORT'].astype(str)
        df['L4_DST_PORT'] = df['L4_DST_PORT'].replace('', 80).astype(int)
        df['L4_SRC_PORT'] = df['L4_SRC_PORT'].replace('', 60881).astype(int)
        df['PROTOCOL'] = df['PROTOCOL'].replace('', 6).astype(int)
        df['TCP_FLAGS'] = df['TCP_FLAGS'].apply(convert_flags_to_int)

        # Return the extracted labels as a JSON response
        # labels = ["Label"] * len(features)  # Replace this with your logic for assigning labels
        print(df.dtypes)
        print(len(features), " : features length")
        print(type(features), " : features type")
        for i in range(10):
            feature_vector = features[i]
            data_types = [type(val) for val in feature_vector]
            print("Data Types for Feature Vector", i, ":", data_types)
            # print(f"IPV4_SRC_ADDR: {feature_vector[0]}, L4_SRC_PORT: {feature_vector[1]}, IPV4_DST_ADDR: {feature_vector[2]}, L4_DST_PORT: {feature_vector[3]}, PROTOCOL: {feature_vector[4]}, TCP_FLAGS: {feature_vector[5]}, FLOW_DURATION_MILLISECONDS: {feature_vector[6]}")

        predictions = model.predict(df)

        # Print or further process the predictions
        for i, prediction in enumerate(predictions):
            print(f"Prediction for Sample {i}: {prediction}")

        predictions_list = predictions.tolist()

        return JSONResponse(content={"predictions": predictions_list})

    except Exception as e:
        return JSONResponse(content={"error": f"An error occurred: {str(e)}"}, status_code=500)

if __name__ == "__main__":
    import uvicorn

    # Start the FastAPI application with Uvicorn
    port = int(os.environ.get("ASGI_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
