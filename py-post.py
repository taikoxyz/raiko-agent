import json
import requests
import sys

def post_proof(input_file):
    with open(input_file, 'rb') as f:
        binary_data = f.read()

    input_bytes = list(binary_data)

    response = requests.post(
        "http://localhost:9999/proof",
        json={
            "input": input_bytes,
            "proof_type": "Batch"
        }
    )

    print(response.json())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)
    post_proof(sys.argv[1])