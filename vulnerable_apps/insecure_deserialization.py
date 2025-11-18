"""
Insecure Deserialization Vulnerability Demo
OWASP A08:2021 - Software and Data Integrity Failures
"""
import pickle
import yaml
import base64

class UserProfile:
    def __init__(self, username, role):
        self.username = username
        self.role = role

    def __reduce__(self):
        # This can be exploited for code execution
        return (eval, ("__import__('os').system('echo Exploited!')",))

def deserialize_user_session(session_data):
    """VULNERABLE: Using pickle to deserialize untrusted data"""
    try:
        # VULNERABLE: pickle.loads() on user-controlled data
        user = pickle.loads(base64.b64decode(session_data))
        return user
    except Exception as e:
        return None

def load_config_from_yaml(yaml_string):
    """VULNERABLE: Unsafe YAML deserialization"""
    # VULNERABLE: yaml.load() without safe loader
    config = yaml.load(yaml_string, Loader=yaml.Loader)
    return config

def restore_object_state(serialized_obj):
    """VULNERABLE: Direct pickle deserialization"""
    # VULNERABLE: No validation of serialized data
    obj = pickle.loads(serialized_obj)
    return obj

class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, user_data):
        """Creates a session with serialized user data"""
        # VULNERABLE: Serializing with pickle
        serialized = pickle.dumps(user_data)
        session_id = base64.b64encode(serialized).decode()
        self.sessions[session_id] = serialized
        return session_id

    def get_session(self, session_id):
        """VULNERABLE: Deserializing user-controlled session data"""
        if session_id in self.sessions:
            # VULNERABLE: No signature verification
            return pickle.loads(self.sessions[session_id])
        return None

def process_uploaded_data(data):
    """VULNERABLE: Processing serialized data from uploads"""
    # VULNERABLE: Trusting uploaded serialized data
    try:
        obj = pickle.loads(data)
        return obj
    except:
        return None

if __name__ == "__main__":
    # Example of creating malicious payload:
    # malicious_user = UserProfile("attacker", "admin")
    # payload = base64.b64encode(pickle.dumps(malicious_user))
    print("Insecure deserialization demo")
