"""
Weak Cryptography Vulnerability Demo
OWASP A02:2021 - Cryptographic Failures
"""
import hashlib
import base64
from Crypto.Cipher import DES, ARC4
import random

def hash_password_md5(password):
    """VULNERABLE: Using MD5 for password hashing"""
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_sha1(password):
    """VULNERABLE: Using SHA1 without salt"""
    # VULNERABLE: SHA1 is weak and no salt is used
    return hashlib.sha1(password.encode()).hexdigest()

def encrypt_data_des(data, key):
    """VULNERABLE: Using DES encryption"""
    # VULNERABLE: DES has a small key size (56 bits)
    cipher = DES.new(key[:8], DES.MODE_ECB)

    # Pad data to 8 bytes
    padded_data = data + ' ' * (8 - len(data) % 8)
    encrypted = cipher.encrypt(padded_data.encode())

    return base64.b64encode(encrypted)

def encrypt_with_rc4(plaintext, key):
    """VULNERABLE: Using RC4 cipher"""
    # VULNERABLE: RC4 has known vulnerabilities
    cipher = ARC4.new(key.encode())
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(encrypted)

def simple_xor_encrypt(data, key):
    """VULNERABLE: XOR encryption"""
    # VULNERABLE: XOR encryption is easily breakable
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    return base64.b64encode(encrypted.encode())

def generate_random_token():
    """VULNERABLE: Weak random number generation"""
    # VULNERABLE: Using predictable random
    token = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    return token

def create_session_id(username):
    """VULNERABLE: Predictable session ID"""
    # VULNERABLE: Session ID based only on username
    return hashlib.md5(username.encode()).hexdigest()

class EncryptionService:
    """VULNERABLE: Poor key management"""
    def __init__(self):
        # VULNERABLE: Hardcoded encryption key
        self.key = b'12345678'  # 8 bytes for DES

    def encrypt(self, data):
        # VULNERABLE: ECB mode (doesn't use IV)
        cipher = DES.new(self.key, DES.MODE_ECB)
        padded = data + ' ' * (8 - len(data) % 8)
        return cipher.encrypt(padded.encode())

def hash_without_salt(data):
    """VULNERABLE: Hashing without salt"""
    # VULNERABLE: Rainbow table attacks possible
    return hashlib.sha256(data.encode()).hexdigest()

def encrypt_password(password):
    """VULNERABLE: Reversible encryption for passwords"""
    # VULNERABLE: Passwords should be hashed, not encrypted
    # Using base64 encoding (not even encryption!)
    return base64.b64encode(password.encode()).decode()

def verify_password(stored, provided):
    """VULNERABLE: Timing attack vulnerability"""
    # VULNERABLE: String comparison vulnerable to timing attacks
    stored_hash = hashlib.md5(stored.encode()).hexdigest()
    provided_hash = hashlib.md5(provided.encode()).hexdigest()

    # VULNERABLE: Direct string comparison
    return stored_hash == provided_hash

def generate_api_key(user_id):
    """VULNERABLE: Weak API key generation"""
    # VULNERABLE: Predictable API key based on user_id
    return hashlib.md5(f"api_key_{user_id}".encode()).hexdigest()

def custom_hash(data):
    """VULNERABLE: Custom/homemade cryptography"""
    # VULNERABLE: Never roll your own crypto!
    result = 0
    for char in data:
        result = ((result << 5) + result) + ord(char)
    return hex(result)

def encrypt_credit_card(card_number):
    """VULNERABLE: Weak encryption for sensitive data"""
    # VULNERABLE: Simple Caesar cipher
    encrypted = ''.join([str((int(d) + 3) % 10) for d in card_number])
    return encrypted

# VULNERABLE: Reusing initialization vectors
GLOBAL_IV = b'12345678'

def aes_encrypt_with_static_iv(data, key):
    """VULNERABLE: Reusing IV across encryptions"""
    from Crypto.Cipher import AES

    # VULNERABLE: Static IV allows pattern detection
    cipher = AES.new(key, AES.MODE_CBC, GLOBAL_IV)
    padded = data + ' ' * (16 - len(data) % 16)
    return cipher.encrypt(padded.encode())

if __name__ == "__main__":
    # Examples of vulnerable cryptography
    print("MD5 hash:", hash_password_md5("password123"))
    print("Token:", generate_random_token())
    print("Encrypted:", simple_xor_encrypt("secret", "key"))
