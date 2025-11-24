import os
import json

def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def read_json(path):
    with open(path, "r") as f:
        return json.load(f)

