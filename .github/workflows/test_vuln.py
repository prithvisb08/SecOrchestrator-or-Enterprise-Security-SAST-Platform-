import hashlib
import os

# Issue 1: Weak Cryptography
password_hash = hashlib.md5(b"password123").hexdigest()

# Issue 2: Code Injection / Unsafe Execution
def run_user_code(user_input):
    exec(user_input)

# Issue 3: Hardcoded Secret / API Key
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"