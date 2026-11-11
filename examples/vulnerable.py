import hashlib
import os

# Weak Cryptography
def hash_password(password):
    h = hashlib.md5(password.encode())
    return h.hexdigest()

# Code Injection
def run_dynamic_code(user_input):
    exec(user_input)

# Hardcoded Secret
AWS_API_KEY = "AKIAIOSFODNN7EXAMPLE"