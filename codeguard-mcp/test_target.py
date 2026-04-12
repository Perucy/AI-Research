# test_target.py
# ---------------------------------------------------------------
# Sample file with intentionally fake credentials for testing
# CodeGuard's scan_file tool.
#
# These are NOT real credentials. They follow common patterns
# that secret scanners look for, allowing you to verify that
# CodeGuard's detection rules fire correctly.
# ---------------------------------------------------------------

import os
import sqlite3

# SEC-001: Hardcoded AWS Secret Access Key pattern
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SEC-002: Hardcoded API key (generic)
api_key = "FAKE_API_KEY_FOR_RESEARCH_ONLY"

# SEC-003: Hardcoded password
password = "SuperFakePassword123!"

# SEC-004: Private key block
# -----BEGIN RSA PRIVATE KEY-----
# (fake key block for pattern matching only)
# -----END RSA PRIVATE KEY-----

# SEC-005: Hardcoded JWT (fake, non-functional)
token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fakesignatureXYZ"

# SEC-006: SQL injection risk pattern
def get_user(user_input):
    conn = sqlite3.connect("db.sqlite")
    conn.execute("SELECT * FROM users WHERE id = " + user_input)

# SEC-007: Path traversal risk pattern
def read_file(param):
    with open(param) as f:
        return f.read()