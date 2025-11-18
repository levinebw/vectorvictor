"""
Hardcoded Secrets and Sensitive Data Exposure
OWASP A02:2021 - Cryptographic Failures
OWASP A05:2021 - Security Misconfiguration
"""
import mysql.connector
import boto3
import requests
from cryptography.fernet import Fernet

# VULNERABLE: Hardcoded database credentials
DB_HOST = "production-db.example.com"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
DB_NAME = "customer_data"

# VULNERABLE: Hardcoded API keys
API_KEY = "sk_live_51HqR8pKx3y9ZfMnO8VqW7uE2aS6dF4gH9jK0lL"
STRIPE_SECRET = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

# VULNERABLE: Hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"

# VULNERABLE: Hardcoded encryption keys
ENCRYPTION_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
SECRET_KEY = "django-insecure-7#h@4vq&amp;$j6x2m9k!p8%r3t2w5e8"

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "my_super_secret_jwt_key_12345"

# VULNERABLE: Hardcoded GitHub token
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# VULNERABLE: Hardcoded private SSH key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz...
-----END RSA PRIVATE KEY-----"""

def connect_to_database():
    """VULNERABLE: Using hardcoded credentials"""
    connection = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    return connection

def upload_to_s3(file_path, bucket_name):
    """VULNERABLE: Hardcoded AWS credentials"""
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    s3_client.upload_file(file_path, bucket_name, 'uploaded_file')

def process_payment(amount, card_token):
    """VULNERABLE: Hardcoded API key in request"""
    headers = {
        'Authorization': f'Bearer {STRIPE_SECRET}',
        'Content-Type': 'application/json'
    }
    response = requests.post(
        'https://api.stripe.com/v1/charges',
        headers=headers,
        json={'amount': amount, 'token': card_token}
    )
    return response.json()

def encrypt_data(data):
    """VULNERABLE: Hardcoded encryption key"""
    cipher = Fernet(ENCRYPTION_KEY)
    encrypted = cipher.encrypt(data.encode())
    return encrypted

def send_email_via_smtp():
    """VULNERABLE: Hardcoded email credentials"""
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "admin@example.com"
    smtp_password = "EmailPassword123!"  # VULNERABLE

    # Email sending logic here
    pass

class APIClient:
    """VULNERABLE: Hardcoded credentials in class"""
    def __init__(self):
        self.api_url = "https://api.example.com"
        self.username = "api_user"
        self.password = "ApiP@ssw0rd123"  # VULNERABLE
        self.api_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # VULNERABLE

    def authenticate(self):
        """Using hardcoded credentials"""
        auth_data = {
            'username': self.username,
            'password': self.password
        }
        return requests.post(f"{self.api_url}/login", json=auth_data)

# VULNERABLE: Slack webhook URL
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"

# VULNERABLE: Database connection string
DATABASE_URL = "postgresql://admin:password123@db.example.com:5432/production"

if __name__ == "__main__":
    print("Hardcoded secrets demo - DO NOT USE IN PRODUCTION!")
