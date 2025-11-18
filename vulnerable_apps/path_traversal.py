"""
Path Traversal Vulnerability Demo
OWASP A01:2021 - Broken Access Control
"""
import os
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download_file():
    """VULNERABLE: Path traversal in file download"""
    filename = request.args.get('file')

    # VULNERABLE: No validation of file path
    file_path = os.path.join('/var/www/uploads/', filename)
    return send_file(file_path)

@app.route('/read')
def read_file():
    """VULNERABLE: Path traversal in file reading"""
    filename = request.args.get('filename')

    # VULNERABLE: Direct file access without sanitization
    with open(f'/app/data/{filename}', 'r') as f:
        content = f.read()

    return content

@app.route('/image')
def serve_image():
    """VULNERABLE: Path traversal in image serving"""
    image_name = request.args.get('img')

    # VULNERABLE: Constructing path with user input
    image_path = './images/' + image_name
    return send_file(image_path)

def load_template(template_name):
    """VULNERABLE: Path traversal in template loading"""
    # VULNERABLE: No path normalization
    template_path = f"templates/{template_name}"

    with open(template_path, 'r') as f:
        return f.read()

def get_user_file(user_id, filename):
    """VULNERABLE: Path traversal in user file access"""
    # VULNERABLE: User-controlled path components
    file_path = f"/home/users/{user_id}/{filename}"

    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            return f.read()
    return None

def read_config(config_name):
    """VULNERABLE: Path traversal in config reading"""
    # VULNERABLE: No validation of config name
    config_path = os.path.join('config', config_name)

    with open(config_path, 'r') as f:
        return f.read()

def delete_upload(upload_id, filename):
    """VULNERABLE: Path traversal in file deletion"""
    # VULNERABLE: Unsanitized filename in deletion
    upload_dir = f'/uploads/{upload_id}/'
    file_to_delete = upload_dir + filename

    if os.path.exists(file_to_delete):
        os.remove(file_to_delete)
        return True
    return False

@app.route('/log')
def view_log():
    """VULNERABLE: Path traversal in log viewing"""
    log_file = request.args.get('logfile', 'app.log')

    # VULNERABLE: No sanitization of log file path
    log_path = os.path.join('/var/log/', log_file)

    try:
        with open(log_path, 'r') as f:
            return '<pre>' + f.read() + '</pre>'
    except:
        return 'Log file not found'

def include_file(filename):
    """VULNERABLE: Path traversal via os.path.join"""
    # VULNERABLE: Even with os.path.join, absolute paths can bypass
    base_dir = '/var/www/includes/'
    file_path = os.path.join(base_dir, filename)

    with open(file_path, 'r') as f:
        return f.read()

def backup_file(source_file):
    """VULNERABLE: Path traversal in backup operations"""
    # VULNERABLE: No validation of source path
    backup_dir = '/backups/'
    backup_path = backup_dir + source_file + '.bak'

    # Reading from potentially dangerous path
    with open(source_file, 'rb') as src:
        with open(backup_path, 'wb') as dst:
            dst.write(src.read())

if __name__ == '__main__':
    # Example exploitation:
    # /download?file=../../etc/passwd
    # /read?filename=../../../../etc/shadow
    # /image?img=../../../secret/keys.txt
    # /log?logfile=../../../../../../etc/passwd
    app.run(debug=True)
