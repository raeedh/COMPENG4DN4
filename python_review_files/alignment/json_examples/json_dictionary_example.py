#!/usr/bin/env python3

import json

# Define a Python dictionary.

d = {
    "name": "John Smith",
    "age" : 30,
    "employer" : "McMaster University"
}

print(type(d))
print(d)

# Serialize it using JSON.
d_json_enc = json.dumps(d)
print(type(d_json_enc))
print(d_json_enc)

# Deserialize it using JSON.
d_json_enc_dec = json.loads(d_json_enc)
print(type(d_json_enc_dec))
print(d_json_enc_dec)

