import jwt
from tkinter import messagebox

def decode_jwt(token):
    """
    Decode JWT header and payload without verifying signature.
    Returns (header, payload) or (None, None) on error.
    """
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        header = jwt.get_unverified_header(token)
        return header, decoded
    except jwt.InvalidTokenError as e:
        messagebox.showerror("Error", f"Invalid JWT: {str(e)}")
        return None, None

def encode_jwt(header, payload, secret, algorithm):
    """
    Encode and sign JWT with given header, payload, secret, and algorithm.
    Returns signed JWT or None on error.
    """
    try:
        return jwt.encode(payload, secret, algorithm=algorithm, headers=header)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to re-sign JWT: {str(e)}")
        return None

def verify_jwt(token, secret, algorithm):
    """
    Verify JWT signature with given secret and algorithm.
    Returns True if valid, False otherwise.
    """
    try:
        jwt.decode(token, secret, algorithms=[algorithm])
        return True
    except jwt.InvalidTokenError:
        return False