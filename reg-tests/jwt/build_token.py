#!/usr/bin/python

# JWT package can be installed via 'pip install pyjwt' command

import sys
import jwt
import json

if len(sys.argv) != 4:
    print(sys.argv[0],"<alg> <json_to_sign> <priv_key>")
    quit()


alg=sys.argv[1]
json_to_sign=sys.argv[2]
priv_key_file=sys.argv[3]

with open(priv_key_file) as file:
    priv_key = file.read()

print(jwt.encode(json.loads(json_to_sign),priv_key,algorithm=alg))

