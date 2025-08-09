from flask import Flask, render_template, request, Response, redirect, url_for, flash ,jsonify , send_file , session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import platform
import subprocess
import socket
from datetime import datetime
import paramiko
import ipaddress
import concurrent.futures
from installer import ClamAVInstaller, install_on_hosts
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent.futures import ThreadPoolExecutor
import concurrent
import json
import time
import subprocess
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import ipaddress
import platform
import os
import re
import psutil
import config
import yara  # For pattern matching
import hashlib  # For file hashing
import magic  # For file type detection
from collections import defaultdict
import pandas as pd
from werkzeug.utils import secure_filename
import uuid
from modules import pcap







app = Flask(__name__)
app.secret_key = config.SECRET_KEY  # Change this to a strong secret key

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Single admin user configuration
ADMIN_USERNAME = config.USERNAME
ADMIN_PASSWORD_HASH = generate_password_hash(f'{config.PASSWORD}')  # Change this password
# Add to your config.py or in the main file
IOC_RULES_DIR = './ioc_rules'  # Directory for YARA rules
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'md', 'conf',
                    'xlsx', 'ppt', 'pptx', 'exe', 'dll', 'js', 'config',
                    'vbs', 'ps1', 'zip', 'rar', '7z',
                    'jpg', 'jpeg', 'png', 'jfif', 'heic', 'pcap', 'pcapng'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size



clamNETApp = os.path.join(config.MAINDIR)  # main path
os.makedirs(clamNETApp, exist_ok=True)

UPLOADS = os.path.join(config.UPLOADDIR)  # main path
os.makedirs(UPLOADS, exist_ok=True)


class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id == ADMIN_USERNAME:
        return User(user_id)
    return None

# Add connection test before main operations
def test_connection(self):
    try:
        transport = self.ssh.get_transport()
        if transport and transport.is_active():
            return True
        return False
    except:
        return False

# Add this near the top of main.py, after the imports
class ClamAVInstaller:
    def __init__(self, host, username, password, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.ssh = None
        self.os_type = None
        self.distro = None

    # In your ClamAVInstaller class, modify the connect method:
    def connect(self, timeout=30):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=timeout,
                banner_timeout=timeout+15,  # Extended banner timeout
                auth_timeout=timeout,
                channel_timeout=timeout
            )
        except Exception as e:
            if self.ssh:
                self.ssh.close()
            raise Exception(f"SSH connection failed: {str(e)}")

    def update_database(self, timeout=300):
        """Update ClamAV virus databases with enhanced OS detection and streaming output"""
        try:
            self.connect()

            # Step 1: Detect OS
            os_type = None
            os_details = "Unknown OS"

            # Try Linux/Unix detection
            stdin, stdout, stderr = self.ssh.exec_command("uname -s")
            uname_output = stdout.read().decode('utf-8', errors='ignore').strip()
            stderr_output = stderr.read().decode('utf-8', errors='ignore').strip()
            if uname_output:
                if "Linux" in uname_output:
                    os_type = 'linux'
                    stdin, stdout, stderr = self.ssh.exec_command("cat /etc/os-release || lsb_release -a || echo 'NO_DISTRO'")
                    os_details = stdout.read().decode('utf-8', errors='ignore').strip() or "Linux (unknown distro)"
                elif "FreeBSD" in uname_output or "SunOS" in uname_output:
                    os_type = None
                    os_details = f"Unsupported Unix-like OS: {uname_output}"

            if not os_type:
                # Try Windows detection
                stdin, stdout, stderr = self.ssh.exec_command("ver")
                ver_output = stdout.read().decode('utf-8', errors='ignore').strip()
                stderr_output = stderr.read().decode('utf-8', errors='ignore').strip()
                if "Microsoft" in ver_output:
                    os_type = 'windows'
                    os_details = f"Windows ({ver_output})"
                else:
                    stdin, stdout, stderr = self.ssh.exec_command("systeminfo")
                    systeminfo_output = stdout.read().decode('utf-8', errors='ignore').strip()
                    if "Microsoft" in systeminfo_output:
                        os_type = 'windows'
                        os_details = f"Windows (detected via systeminfo)"
                    else:
                        os_details = f"Failed to detect OS: uname='{uname_output}', ver='{ver_output}', systeminfo='{systeminfo_output[:100]}...'"

            if not os_type:
                return False, f"Unsupported operating system: {os_details}"

            self.os_type = os_type

            # Step 2: Execute freshclam command
            output = []
            if os_type == 'linux':
                cmd = "sudo freshclam --verbose"
                exit_status, stdout, stderr = self.execute_command(cmd, timeout)
                output.append(stdout)
                if stderr:
                    output.append(f"Error: {stderr}")
                if exit_status != 0:
                    return False, '\n'.join(output) or "Update failed: No output"
            elif os_type == 'windows':
                cmd = '"C:\\Program Files\\ClamAV\\freshclam.exe" --verbose'
                chan = self.ssh.get_transport().open_session()
                chan.settimeout(timeout)
                chan.exec_command(cmd)
                while not chan.exit_status_ready():
                    if chan.recv_ready():
                        output.append(chan.recv(1024).decode('utf-8', errors='ignore'))
                    if chan.recv_stderr_ready():
                        output.append(chan.recv_stderr(1024).decode('utf-8', errors='ignore'))
                    time.sleep(0.1)
                if chan.recv_ready():
                    output.append(chan.recv(1024).decode('utf-8', errors='ignore'))
                if chan.recv_stderr_ready():
                    output.append(chan.recv_stderr(1024).decode('utf-8', errors='ignore'))
                exit_status = chan.recv_exit_status()
                if exit_status != 0:
                    return False, '\n'.join(output) or "Update failed: No output"

            output_str = '\n'.join(output).strip()
            return True, output_str

        except socket.timeout:
            return False, "Operation timed out"
        except paramiko.AuthenticationException:
            return False, "Authentication failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {str(e)}"
        except Exception as e:
            return False, f"Update error: {str(e)}"
        finally:
            if hasattr(self, 'ssh') and self.ssh:
                self.ssh.close()

    def execute_command(self, command, wait=True):
        """Execute a command on the remote host with proper sudo handling"""
        # Handle sudo commands differently
        if command.startswith("sudo ") or command in ["apt-get update", "apt-get install", "dnf install", "yum install", "zypper install"]:
            full_command = f"echo '{self.password}' | sudo -S bash -c '{command}'"
        else:
            full_command = command
        
        stdin, stdout, stderr = self.ssh.exec_command(full_command)
        if wait:
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            return exit_status, output, error
        return None, None, None

    def install_linux(self):
        """Install ClamAV on Linux based on distribution"""
        if self.distro in ['ubuntu', 'debian']:
            commands = [
                "sudo apt-get update -o DPkg::Lock::Timeout=60",
                "sudo apt-get install -y clamav clamav-daemon"
            ]
        elif self.distro in ['centos', 'fedora', 'rocky', 'almalinux']:
            commands = [
                "sudo dnf install -y clamav clamd clamav-update || sudo yum install -y clamav clamd clamav-update"
            ]
        elif self.distro == 'opensuse':
            commands = [
                "sudo zypper --non-interactive install clamav"
            ]
        else:
            return False, "Unsupported Linux distribution"

        for cmd in commands:
            exit_status, _, error = self.execute_command(cmd)
            if exit_status != 0:
                return False, f"Installation failed: {error}"

        return True, "ClamAV installed successfully on Linux"

    def install_windows(self):
        """Install ClamAV on Windows using local MSI file"""
        try:
            # Copy the local MSI file to the remote system
            local_msi_path = "clamav-1.4.3.win.x64.msi"  # Path on admin system
            remote_msi_path = "clamav-installer.msi"     # Path on remote system
            
            copy_cmd = f"powershell -Command \"Copy-Item -Path '{local_msi_path}' -Destination '{remote_msi_path}'\""
            exit_status, _, error = self.execute_command(copy_cmd)
            if exit_status != 0:
                return False, f"File copy failed: {error}"

            # Install from the copied MSI file
            install_cmd = (
                "msiexec /i clamav-installer.msi /quiet /qn /norestart "
                "ADDLOCAL=ALL INSTALLDIR=\"C:\\Program Files\\ClamAV\""
            )
            exit_status, _, error = self.execute_command(install_cmd)
            if exit_status != 0:
                return False, f"Installation failed: {error}"

            time.sleep(30)

            config_commands = [
                "mkdir \"C:\\Program Files\\ClamAV\\database\"",
                "copy \"C:\\Program Files\\ClamAV\\conf_examples\\clamd.conf.sample\" \"C:\\Program Files\\ClamAV\\clamd.conf\"",
                "copy \"C:\\Program Files\\ClamAV\\conf_examples\\freshclam.conf.sample\" \"C:\\Program Files\\ClamAV\\freshclam.conf\"",
                "(Get-Content \"C:\\Program Files\\ClamAV\\clamd.conf\") | " +
                "ForEach-Object { $_ -replace '^Example', '#Example' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\clamd.conf\"",
                # ... (keep all other config commands)
            ]

            for cmd in config_commands:
                exit_status, _, error = self.execute_command(cmd)
                if exit_status != 0:
                    return False, f"Configuration failed: {error}"

            return True, "ClamAV installed and configured successfully on Windows"
        except Exception as e:
            return False, f"Windows installation error: {str(e)}"

    def install(self):
        """Main installation method"""
        try:
            self.connect()
            
            if self.os_type == 'linux':
                return self.install_linux()
            elif self.os_type == 'windows':
                return self.install_windows()
            else:
                return False, "Unsupported operating system"
        except Exception as e:
            return False, f"Connection/Installation error: {str(e)}"
        finally:
            if self.ssh:
                self.ssh.close()

def install_on_hosts(hosts, username, password, max_threads=5):
    """Install ClamAV on multiple hosts in parallel"""
    results = []
    
    def process_host(host):
        installer = ClamAVInstaller(host, username, password)
        success, message = installer.install()
        return {
            'host': host,
            'success': success,
            'message': message
        }
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(process_host, host) for host in hosts]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    
    return results


def update_database(self, timeout=300):
    """Update ClamAV virus databases with streaming output"""
    try:
        self.connect()

        # Detect OS
        stdin, stdout, stderr = self.ssh.exec_command("uname")
        os_type = stdout.read().decode().strip()
        if "Linux" in os_type:
            self.os_type = 'linux'
            cmd = "sudo freshclam --verbose"
        else:
            stdin, stdout, stderr = self.ssh.exec_command("ver")
            if "Microsoft" in stdout.read().decode():
                self.os_type = 'windows'
                cmd = '"C:\\Program Files\\ClamAV\\freshclam.exe" --verbose'
            else:
                return False, "Unsupported operating system"

        # Execute command with streaming
        chan = self.ssh.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(cmd)

        output = []
        while not chan.exit_status_ready():
            if chan.recv_ready():
                data = chan.recv(1024).decode('utf-8', errors='ignore')
                output.append(data)
            if chan.recv_stderr_ready():
                error = chan.recv_stderr(1024).decode('utf-8', errors='ignore')
                output.append(f"Error: {error}")
            time.sleep(0.1)

        # Read any remaining output
        if chan.recv_ready():
            output.append(chan.recv(1024).decode('utf-8', errors='ignore'))
        if chan.recv_stderr_ready():
            output.append(chan.recv_stderr(1024).decode('utf-8', errors='ignore'))

        exit_status = chan.recv_exit_status()
        output_str = ''.join(output).strip()

        if exit_status != 0:
            return False, f"Update failed: {output_str}"
        return True, output_str

    except socket.timeout:
        return False, "Operation timed out"
    except paramiko.AuthenticationException:
        return False, "Authentication failed"
    except paramiko.SSHException as e:
        return False, f"SSH error: {str(e)}"
    except Exception as e:
        return False, f"Update error: {str(e)}"
    finally:
        if self.ssh:
            self.ssh.close()


class IOCScanner:
    def __init__(self):
        self.yara_rules = self._load_yara_rules()
        self.ioc_database = self._load_ioc_database()
        
    def _load_yara_rules(self):
        """Load YARA rules from the rules directory"""
        rules = {}
        yara_dir = os.path.join(IOC_RULES_DIR, 'yara')
        
        try:
            if not os.path.exists(yara_dir):
                os.makedirs(yara_dir, exist_ok=True)
                # Download default rules if directory was just created
                self._download_default_rules()
                return rules
                
            for rule_file in os.listdir(yara_dir):
                if rule_file.endswith(('.yar', '.yara')):
                    try:
                        rule_path = os.path.join(yara_dir, rule_file)
                        rules[rule_file] = yara.compile(filepath=rule_path)
                    except yara.Error as e:
                        print(f"Error loading YARA rule {rule_file}: {str(e)}")
        except Exception as e:
            print(f"Error loading YARA rules: {str(e)}")
        return rules
        
    def _load_ioc_database(self):
        """Load IOC database (hashes, domains, IPs)"""
        db_path = os.path.join(IOC_RULES_DIR, 'ioc_database.json')
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    return json.load(f)
            except:
                return {'hashes': [], 'domains': [], 'ips': []}
        return {'hashes': [], 'domains': [], 'ips': []}
        
    def scan_file(self, file_path):
        """Scan a file for IOCs"""
        results = {
            'basic_info': {},
            'yara_matches': [],
            'ioc_matches': [],
            'threat_score': 0
        }
        
        try:
            # Get basic file info
            file_stats = os.stat(file_path)
            results['basic_info'] = {
                'filename': os.path.basename(file_path),
                'size': file_stats.st_size,
                'created': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                'file_type': magic.from_file(file_path),
                'md5': self._calculate_hash(file_path, 'md5'),
                'sha1': self._calculate_hash(file_path, 'sha1'),
                'sha256': self._calculate_hash(file_path, 'sha256')
            }
            
            # Check against known IOCs
            file_hash = results['basic_info']['sha256']
            if file_hash in self.ioc_database['hashes']:
                results['ioc_matches'].append({
                    'type': 'hash',
                    'value': file_hash,
                    'severity': 'high'
                })
                results['threat_score'] += 80
                
            # Scan with YARA rules
            for rule_name, rule in self.yara_rules.items():
                try:
                    matches = rule.match(file_path)
                    if matches:
                        results['yara_matches'].extend([{
                            'rule': rule_name,
                            'tags': match.tags,
                            'meta': match.meta,
                            'strings': [str(s) for s in match.strings]
                        } for match in matches])
                        # Increase threat score based on rule severity
                        severity = matches[0].meta.get('severity', 'medium').lower()
                        if severity == 'high':
                            results['threat_score'] += 50
                        elif severity == 'medium':
                            results['threat_score'] += 30
                        else:
                            results['threat_score'] += 10
                except:
                    continue
                    
            # Determine overall threat level
            results['threat_level'] = self._determine_threat_level(results['threat_score'])
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
        
    def _calculate_hash(self, file_path, algorithm='sha256'):
        """Calculate file hash using specified algorithm"""
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
        
    def _determine_threat_level(self, score):
        """Convert threat score to human-readable level"""
        if score >= 80:
            return 'Critical'
        elif score >= 50:
            return 'High'
        elif score >= 30:
            return 'Medium'
        elif score >= 10:
            return 'Low'
        return 'None'

@app.route('/update-databases')
@login_required
def update_databases():
    session_token = request.args.get('session_token', '')
    if session_token not in session_store:
        def generate():
            yield "data: ❌ Invalid or expired session token\n\n"
        return Response(generate(), mimetype='text/event-stream')

    session = session_store[session_token]
    hosts = session['hosts'].split(',')
    username = session['username']
    password = session['password']

    def generate():
        try:
            # Validate inputs
            if not hosts or not username or not password:
                yield "data: ❌ Missing hosts, username, or password\n\n"
                return

            # Validate IP addresses
            valid_hosts = []
            for host in hosts:
                host = host.strip()
                try:
                    ipaddress.ip_address(host)
                    valid_hosts.append(host)
                except ValueError:
                    yield f"data: ❌ Invalid IP address: {host}\n\n"
                    continue

            if not valid_hosts:
                yield "data: ❌ No valid hosts provided\n\n"
                return

            yield "data: 🔄 Starting database update on remote hosts...\n\n"

            total_hosts = len(valid_hosts)
            progress_per_host = 100.0 / total_hosts
            current_progress = 0

            def process_host(host):
                installer = ClamAVInstaller(host, username, password)
                try:
                    success, message = installer.update_database()
                    return host, success, message
                except Exception as e:
                    return host, False, f"Update failed: {str(e)}"
                finally:
                    if installer.ssh:
                        installer.ssh.close()

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(process_host, host) for host in valid_hosts]
                for future in concurrent.futures.as_completed(futures):
                    host, success, message = future.result()
                    current_progress += progress_per_host
                    yield f"data: PROGRESS:{min(round(current_progress), 100)}\n\n"
                    status = "✅" if success else "❌"
                    for line in message.split('\n'):
                        if line.strip():
                            yield f"data: {status} {host}: {line.strip()}\n\n"

            yield "data: COMPLETED\n\n"
            yield "data: END\n\n"

        except GeneratorExit:
            yield "data: 🔌 Client disconnected\n\n"
        except Exception as e:
            yield f"data: ❌ Global error: {str(e)}\n\n"
        finally:
            if session_token in session_store:
                del session_store[session_token]

    response = Response(generate(), mimetype='text/event-stream')
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Cache-Control'] = 'no-cache'
    return response

# Add this to your template routes
@app.route('/update')
@login_required
def update_page():
    return render_template(
        'update.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )






# Temporary session store (use Redis in production)
session_store = {}

@app.route('/start-update-session', methods=['POST'])
@login_required
def start_update_session():
    try:
        data = request.get_json()
        hosts = data.get('hosts', '')
        username = data.get('username', '')
        password = data.get('password', '')

        if not hosts or not username or not password:
            return jsonify({'success': False, 'message': 'Missing hosts, username, or password'}), 400

        session_token = str(uuid.uuid4())
        session_store[session_token] = {
            'hosts': hosts,
            'username': username,
            'password': password,
            'created_at': time.time()
        }

        # Clean up old sessions
        for token, session in list(session_store.items()):
            if time.time() - session['created_at'] > 3600:  # 1 hour TTL
                del session_store[token]

        return jsonify({'success': True, 'session_token': session_token})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            user = User(username)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def scan_network_for_clamav(network_range, username, password):
    """Scan a network range to find hosts with ClamAV installed"""
    hosts = []
    try:
        network = ipaddress.ip_network(network_range, strict=False)
    except ValueError:
        raise Exception("Invalid network range")
    
    def check_host(ip):
        try:
            # First check if SSH is available
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=str(ip), username=username, password=password, timeout=5)
            
            # First try Linux check
            stdin, stdout, stderr = ssh.exec_command("clamscan --version 2>&1 || echo 'NOT_FOUND'")
            clamav_check = stdout.read().decode().strip()
            
            if "NOT_FOUND" not in clamav_check and "clamscan" in clamav_check:
                return (str(ip), True, "Linux")
            
            # If Linux check failed, try Windows check
            win_check_cmd = 'if exist "C:\\Program Files\\ClamAV\\clamscan.exe" (echo FOUND) else (echo NOT_FOUND)'
            stdin, stdout, stderr = ssh.exec_command(f'cmd /c "{win_check_cmd}"')
            win_check = stdout.read().decode().strip()
            
            if "FOUND" in win_check:
                return (str(ip), True, "Windows")
            
            return (str(ip), False, "Unknown")
        except Exception as e:
            return (str(ip), False, f"Error: {str(e)}")
        finally:
            try:
                ssh.close()
            except:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_host, ip) for ip in network.hosts()]
        for future in concurrent.futures.as_completed(futures):
            ip, has_clamav, os_type = future.result()
            hosts.append({
                "ip": ip, 
                "has_clamav": has_clamav,
                "os_type": os_type
            })

    return hosts

def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_os():
    return platform.system()

def build_command(path):
    if get_os() == "Windows":
        return [r"C:\Program Files\ClamAV\clamscan.exe", "--recursive", "--infected", "--verbose", path]
    else:
        return ["clamscan", "--recursive", "--infected", "--verbose", path]

def ssh_scan(host, username, password, path):
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=username, password=password)

    # Detect OS: Try Linux first, then Windows
    stdin, stdout, stderr = ssh.exec_command("uname")
    remote_os = stdout.read().decode().strip()

    if "Linux" in remote_os:
        scan_cmd = f"clamscan --recursive --infected --verbose {path}"
    else:
        # Try Windows detection
        stdin, stdout, stderr = ssh.exec_command("ver")
        windows_check = stdout.read().decode().strip()
        if "Microsoft" in windows_check:
            remote_os = "Windows"
            scan_cmd = f'"C:\\Program Files\\ClamAV\\clamscan.exe" --recursive --infected --verbose {path}'
        else:
            remote_os = "Unknown"
            scan_cmd = None

    if not scan_cmd:
        raise Exception("Unsupported OS or failed to detect remote OS")

    # Run Scan
    stdin, stdout, stderr = ssh.exec_command(scan_cmd)
    return remote_os, stdout, stderr


def humanize_bytes(num, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f} P{suffix}"

app.jinja_env.filters['humanize_bytes'] = humanize_bytes



@app.route('/')
@login_required
def index():
    cpu_percent = psutil.cpu_percent(interval=0.5)
    ram_percent = psutil.virtual_memory().percent
    net_io = psutil.net_io_counters()

    return render_template(
        'main.html',
        os=get_os(),
        ip=get_lan_ip(),
        clamav_path_linux="/usr/bin/clamscan",
        clamav_db_path_linux="/var/lib/clamav",
        clamav_path_windows="C:\\Program Files\\ClamAV\\clamscan.exe",
        clamav_db_path_windows="C:\\Program Files\\ClamAV\\database",
        time=datetime.now().strftime("%H:%M"),
        cpu=cpu_percent,
        ram=ram_percent,
        net_packets_sent=net_io.packets_sent,
        net_packets_recv=net_io.packets_recv,
        net_bytes_sent=net_io.bytes_sent,
        net_bytes_recv=net_io.bytes_recv
    )



@app.route('/scan')
@login_required
def scan_page():
    return render_template(
        'scan.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )


@app.route('/install')
@login_required
def install_page():
    return render_template(
        'install.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/network-scan')
@login_required
def network_scan_page():
    return render_template(
        'network_scan.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

# Add the scan endpoint with login protection
@app.route('/perform-scan')
@login_required
def scan():
    path = request.args.get("scan_path")
    remote_host = request.args.get("remote_host")
    username = request.args.get("remote_user")
    password = request.args.get("remote_pass")

    def generate():
        yield "data: 🔄 Starting scan...\n\n"
        try:
            if remote_host:
                # SSH mode
                yield f"data: 🔗 Connecting to remote host {remote_host}...\n\n"
                remote_os, stdout, stderr = ssh_scan(remote_host, username, password, path)
                yield f"data: 💻 Remote OS: {remote_os}\n\n"
                for line in iter(stdout.readline, ""):
                    yield f"data: {line.strip()}\n\n"
                yield "data: ✅ Remote scan finished.\n\n"
            else:
                # Local scan
                process = subprocess.Popen(build_command(path), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in iter(process.stdout.readline, ''):
                    yield f"data: {line.strip()}\n\n"
                process.stdout.close()
                process.wait()
                yield "data: ✅ Local scan finished.\n\n"
        except Exception as e:
            yield f"data: ❌ Error: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/perform-install', methods=['POST'])
@login_required
def install():
    hosts = [h.strip() for h in request.form.get("install_hosts", "").split(',') if h.strip()]
    username = request.form.get("install_user", "")
    password = request.form.get("install_pass", "")
    
    def generate():
        yield "data: 🔧 Starting ClamAV installation on remote hosts...\n\n"
        if not hosts:
            yield "data: ❌ No valid hosts provided\n\n"
            return
            
        try:
            # Add debug output
            yield f"data: ⚙️ Attempting to install on {len(hosts)} hosts...\n\n"
            
            for host in hosts:
                yield f"data: 🔌 Connecting to {host}...\n\n"
                try:
                    installer = ClamAVInstaller(host, username, password)
                    success, message = installer.install()
                    status = "✅" if success else "❌"
                    yield f"data: {status} {host}: {message}\n\n"
                except Exception as e:
                    yield f"data: ❌ {host} failed: {str(e)}\n\n"
                    continue
                    
            yield "data: 🏁 Installation process completed\n\n"
        except Exception as e:
            yield f"data: ❌ Global installation error: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

def get_os_from_ttl(ttl):
    try:
        ttl = int(ttl)
        if ttl <= 64:
            return "Linux"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Router"
    except:
        return "Unknown"
    return "Unknown"

def ping_host(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        output = subprocess.check_output(['ping', param, '1', '-W', '1', ip], stderr=subprocess.DEVNULL, universal_newlines=True)
        ttl_match = re.search(r'ttl[=|:](\d+)', output.lower())
        ttl = ttl_match.group(1) if ttl_match else "Unknown"
        os = get_os_from_ttl(ttl)

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        return {'ip': ip, 'hostname': hostname, 'ttl': ttl, 'os': os}
    except:
        return None

def scan_network_topology(network_cidr):
    network = ipaddress.ip_network(network_cidr, strict=False)
    hosts_info = []

    for ip in network.hosts():
        ip_str = str(ip)
        info = ping_host(ip_str)
        if info:
            hosts_info.append(info)

    return hosts_info

# @app.route('/scan_map')
# def scan_map():
#     network = request.args.get('network', '192.168.1.0/24')
#     hosts = scan_network_topology(network)
#     return render_template('network_map.html', hosts=hosts, network=network)


@app.route('/ioc-scan')
@login_required
def ioc_scan_page():
    return render_template(
        'ioc_scan.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/upload-ioc-file', methods=['POST'])
@login_required
def upload_ioc_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE:
        return jsonify({'success': False, 'message': 'File size exceeds maximum allowed (100MB)'}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)
        
        # Scan the file without saving results
        scanner = IOCScanner()
        results = scanner.scan_file(upload_path)
        
        # Clean up
        os.remove(upload_path)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    return jsonify({'success': False, 'message': 'Invalid file type'}), 400



@app.route('/perform-ioc-scan', methods=['POST'])
@login_required
def perform_ioc_scan():
    data = request.get_json()
    path = data.get('path')
    remote_host = data.get('remote_host')
    username = data.get('username')
    password = data.get('password')
    
    def generate():
        scanner = IOCScanner()
        
        if remote_host:
            # Remote scanning
            yield "data: 🔍 Starting remote IOC scan...\n\n"
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(remote_host, username=username, password=password)
                
                sftp = ssh.open_sftp()
                remote_files = sftp.listdir(path)
                
                for file in remote_files:
                    remote_path = f"{path}/{file}" if not path.endswith('/') else f"{path}{file}"
                    try:
                        # Download file temporarily
                        local_path = f"/tmp/{file}"
                        sftp.get(remote_path, local_path)
                        
                        # Scan file
                        results = scanner.scan_file(local_path)
                        yield f"data: 📄 {file} - Threat Level: {results['threat_level']}\n\n"
                        if results.get('yara_matches'):
                            for match in results['yara_matches']:
                                yield f"data: ⚠️ YARA Rule Match: {match['rule']}\n\n"
                        if results.get('ioc_matches'):
                            for match in results['ioc_matches']:
                                yield f"data: ⚠️ Known IOC Match: {match['value']}\n\n"
                                
                        # Clean up
                        os.remove(local_path)
                    except Exception as e:
                        yield f"data: ❌ Error scanning {file}: {str(e)}\n\n"
                        continue
                        
                ssh.close()
                yield "data: ✅ Remote IOC scan completed\n\n"
            except Exception as e:
                yield f"data: ❌ Remote scan failed: {str(e)}\n\n"
        else:
            # Local scanning
            yield "data: 🔍 Starting local IOC scan...\n\n"
            try:
                if os.path.isfile(path):
                    results = scanner.scan_file(path)
                    yield f"data: 📄 {os.path.basename(path)} - Threat Level: {results['threat_level']}\n\n"
                    if results.get('yara_matches'):
                        for match in results['yara_matches']:
                            yield f"data: ⚠️ YARA Rule Match: {match['rule']}\n\n"
                    if results.get('ioc_matches'):
                        for match in results['ioc_matches']:
                            yield f"data: ⚠️ Known IOC Match: {match['value']}\n\n"
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                results = scanner.scan_file(file_path)
                                if results['threat_level'] != 'None':
                                    yield f"data: 📄 {file} - Threat Level: {results['threat_level']}\n\n"
                                    if results.get('yara_matches'):
                                        for match in results['yara_matches']:
                                            yield f"data: ⚠️ YARA Rule Match: {match['rule']}\n\n"
                                    if results.get('ioc_matches'):
                                        for match in results['ioc_matches']:
                                            yield f"data: ⚠️ Known IOC Match: {match['value']}\n\n"
                            except Exception as e:
                                yield f"data: ❌ Error scanning {file}: {str(e)}\n\n"
                                continue
                yield "data: ✅ Local IOC scan completed\n\n"
            except Exception as e:
                yield f"data: ❌ Local scan failed: {str(e)}\n\n"
                
    return Response(generate(), mimetype='text/event-stream')







@app.route('/cfg-analysis')
@login_required
def cfg_analyze_page():
    return render_template(
        'ioc_scan.html',  # Changed to dedicated template
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/analyze-cfg', methods=['POST'])
@login_required
def analyze_cfg():
    """Endpoint for analyzing control-flow obfuscation"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
        
    try:
        # Save the uploaded file temporarily
        temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'cf_analysis')
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, secure_filename(file.filename))
        file.save(file_path)
        
        # Initialize the CFG analyzer with enhanced capabilities
        analyzer = EnhancedCFGAnalyzer()
        
        # Perform the analysis
        results = analyzer.analyze_file(file_path)
        
        # Clean up
        os.remove(file_path)
        
        # Render results in template
        return render_template(
            'cfg_results.html',
            results=results,
            filename=file.filename,
            os=get_os(),
            ip=get_lan_ip(),
            time=datetime.now().strftime("%H:%M:%S")
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Analysis failed: {str(e)}'
        }), 500

class EnhancedCFGAnalyzer:
    """Enhanced CFG analyzer with PE analysis and disassembly capabilities"""
    
    def __init__(self):
        self.unicorn_available = self._check_unicorn()
        self.lief_available = self._check_lief()
        
    def _check_unicorn(self):
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
            return True
        except ImportError:
            return False
            
    def _check_lief(self):
        try:
            import lief
            return True
        except ImportError:
            return False
    
    def analyze_file(self, file_path):
        """Comprehensive file analysis with PE parsing and disassembly"""
        results = {
            'file_info': {},
            'pe_analysis': {},
            'disassembly': [],
            'cfg_analysis': {
                'dispatchers': [],
                'deobfuscated': [],
                'statistics': {}
            },
            'warnings': []
        }
        
        try:
            # Basic file info
            results['file_info'] = {
                'filename': os.path.basename(file_path),
                'size': os.path.getsize(file_path),
                'md5': self._calculate_md5(file_path)
            }
            
            # PE Analysis with LIEF
            if self.lief_available:
                results['pe_analysis'] = self._analyze_pe(file_path)
            else:
                results['warnings'].append("LIEF not available - skipping PE analysis")
            
            # Disassembly
            results['disassembly'] = self._disassemble_file(file_path)
            
            # CFG Analysis
            if self.unicorn_available:
                with open(file_path, 'rb') as f:
                    binary_data = f.read()
                
                # Find and analyze dispatchers
                dispatchers = self._find_dispatchers(binary_data)
                results['cfg_analysis']['statistics']['total_dispatchers'] = len(dispatchers)
                
                for disp in dispatchers[:100]:  # Limit to first 100 for performance
                    try:
                        analysis = self._analyze_dispatcher(binary_data, disp['offset'])
                        if analysis:
                            results['cfg_analysis']['deobfuscated'].append(analysis)
                    except Exception as e:
                        results['warnings'].append(f"Dispatcher analysis error at {hex(disp['offset'])}: {str(e)}")
            else:
                results['warnings'].append("Unicorn not available - skipping CFG analysis")
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def _calculate_md5(self, file_path):
        """Calculate MD5 hash of the file"""
        import hashlib
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    
    def _analyze_pe(self, file_path):
        """Analyze PE file using LIEF with version-agnostic resource handling"""
        import lief
        binary = lief.parse(file_path)
        
        if not binary:
            return {"error": "Not a valid PE file"}
            
        pe_info = {
            'header': {
                'machine': str(binary.header.machine),
                'characteristics': [str(c) for c in binary.header.characteristics_list],
                'timestamp': binary.header.time_date_stamps
            },
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': []
        }
        
        # Sections (unchanged)
        for section in binary.sections:
            pe_info['sections'].append({
                'name': section.name,
                'virtual_size': hex(section.virtual_size),
                'size': hex(section.size),
                'entropy': section.entropy,
                'characteristics': [str(c) for c in section.characteristics_lists]
            })
        
        # Imports (unchanged)
        if binary.has_imports:
            for imp in binary.imports:
                import_entry = {
                    'name': imp.name,
                    'entries': []
                }
                for entry in imp.entries:
                    entry_info = {
                        'name': entry.name if entry.name else f"ordinal_{entry.ordinal}",
                        'iat_address': hex(entry.iat_address) if hasattr(entry, 'iat_address') else 'N/A'
                    }
                    import_entry['entries'].append(entry_info)
                pe_info['imports'].append(import_entry)
        
        # Exports (unchanged)
        if binary.has_exports:
            for exp in binary.exported_functions:
                pe_info['exports'].append({
                    'name': exp.name,
                    'address': hex(exp.address)
                })
        
        # Resources - version-agnostic handling
        if binary.has_resources:
            try:
                if hasattr(binary.resources, 'childs'):  # New LIEF versions
                    pe_info['resources'] = self._parse_resource_node(binary.resources)
                else:  # Old LIEF versions
                    pe_info['resources'] = self._parse_legacy_resources(binary.resources)
            except Exception as e:
                pe_info['resources'] = [{'error': f"Resource parsing failed: {str(e)}"}]
        
        return pe_info

    def _parse_resource_node(self, node, level=0):
        """Parse resource directory node (new LIEF versions)"""
        resources = []
        
        if hasattr(node, 'childs'):
            for child in node.childs:
                if child.is_directory:
                    resources.extend(self._parse_resource_node(child, level+1))
                else:
                    resource_data = {
                        'level': level,
                        'size': getattr(child, 'size', 0),
                        'offset': hex(getattr(child, 'offset_to_data', 0)),
                        'name': getattr(child, 'name', f"ID:{getattr(child, 'id', 'N/A')}"),
                        'type': self._get_resource_type(child)
                    }
                    resources.append(resource_data)
        
        return resources

    def _parse_legacy_resources(self, resources):
        """Parse resources for older LIEF versions"""
        parsed = []
        for resource in resources.entries:
            try:
                parsed.append({
                    'type': str(resource.type),
                    'name': resource.name if hasattr(resource, 'name') and resource.name else f"ID:{resource.id}",
                    'size': resource.size,
                    'level': 0,
                    'offset': hex(resource.offset_to_data) if hasattr(resource, 'offset_to_data') else 'N/A'
                })
            except Exception:
                continue
        return parsed

    def _get_resource_type(self, resource):
        """Safely get resource type across LIEF versions"""
        if hasattr(resource, 'type'):
            return str(resource.type)
        if hasattr(resource, 'id'):
            return self._map_resource_id(resource.id)
        return "UNKNOWN"

    def _map_resource_id(self, id):
        """Map resource IDs to human-readable names"""
        types = {
            1: "CURSOR",
            2: "BITMAP",
            3: "ICON",
            4: "MENU",
            5: "DIALOG",
            6: "STRING",
            7: "FONTDIR",
            8: "FONT",
            9: "ACCELERATOR",
            10: "RCDATA",
            11: "MESSAGETABLE",
            12: "GROUP_CURSOR",
            14: "GROUP_ICON",
            16: "VERSION",
            17: "DLGINCLUDE",
            19: "PLUGPLAY",
            20: "VXD",
            21: "ANICURSOR",
            22: "ANIICON",
            23: "HTML",
            24: "MANIFEST"
        }
        return types.get(id, f"UNKNOWN_{id}")
    
    def _disassemble_file(self, file_path, limit=1000):
        """Disassemble the file using capstone"""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
            
            with open(file_path, 'rb') as f:
                code = f.read()
            
            # Try 64-bit first
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            disasm = []
            count = 0
            
            for i in md.disasm(code, 0x1000):
                disasm.append({
                    'address': hex(i.address),
                    'bytes': i.bytes.hex(),
                    'mnemonic': i.mnemonic,
                    'op_str': i.op_str
                })
                count += 1
                if count >= limit:
                    break
            
            return disasm
            
        except ImportError:
            return [{"error": "Capstone not available for disassembly"}]
        except Exception as e:
            return [{"error": f"Disassembly failed: {str(e)}"}]
    
    def _find_dispatchers(self, binary_data):
        """Find potential dispatchers with more patterns"""
        dispatchers = []
        patterns = [
            (b'\x48\xFF\xD0', 'CALL RAX'),  # 64-bit
            (b'\xFF\xD0', 'CALL EAX'),       # 32-bit
            (b'\x48\xFF\xE0', 'JMP RAX'),    # 64-bit
            (b'\xFF\xE0', 'JMP EAX'),        # 32-bit
            (b'\xFF\xD1', 'CALL ECX'),       # Common in obfuscation
            (b'\xFF\xD2', 'CALL EDX'),
            (b'\xFF\xD3', 'CALL EBX'),
            (b'\xFF\x14\x25', 'CALL DWORD PTR'),  # Memory-based dispatchers
            (b'\xFF\x24\x25', 'JMP DWORD PTR')
        ]
        
        for pattern, insn_type in patterns:
            offset = 0
            while True:
                offset = binary_data.find(pattern, offset)
                if offset == -1:
                    break
                dispatchers.append({
                    'offset': offset,
                    'type': insn_type,
                    'bytes': pattern.hex()
                })
                offset += len(pattern)
                
        return dispatchers
    
    def _analyze_dispatcher(self, binary_data, offset, window_size=128):
        """Enhanced dispatcher analysis with context"""
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_ERR_OK
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RFLAGS
        
        try:
            # Extract code window
            start = max(0, offset - window_size)
            end = min(len(binary_data), offset + window_size)
            code = binary_data[start:end]
            adjusted_offset = offset - start
            
            # Initialize emulator
            BASE = 0x100000
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(BASE, 0x10000)
            mu.mem_write(BASE, code)
            
            # Test flag states
            def run_emulation(zf, cf):
                try:
                    mu.reg_write(UC_X86_REG_RFLAGS, (zf << 6) | cf)
                    mu.reg_write(UC_X86_REG_RAX, 0)
                    mu.emu_start(BASE, BASE + adjusted_offset)
                    mu.emu_start(BASE + adjusted_offset, BASE + adjusted_offset + 3)
                    return mu.reg_read(UC_X86_REG_RAX)
                except Exception:
                    return 0
                    
            target_false = run_emulation(zf=0, cf=0)
            target_true = run_emulation(zf=1, cf=1)
            
            # Get disassembly context
            disasm_context = self._get_disasm_context(binary_data, offset)
            
            return {
                'offset': hex(offset),
                'type': 'CALL' if binary_data[offset] in (0xFF, 0x48 and binary_data[offset+1] == 0xD0) else 'JMP',
                'target_false': hex(target_false),
                'target_true': hex(target_true),
                'disassembly': disasm_context,
                'bytes': binary_data[max(0,offset-8):min(len(binary_data),offset+8)].hex()
            }
        except Exception as e:
            return {
                'offset': hex(offset),
                'error': str(e)
            }
    
    def _get_disasm_context(self, binary_data, offset, context_size=5):
        """Get disassembly context around the offset"""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            
            start = max(0, offset - (context_size * 8))
            end = min(len(binary_data), offset + (context_size * 8))
            code = binary_data[start:end]
            
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            
            context = []
            for i in md.disasm(code, 0):
                context.append({
                    'address': hex(i.address + start),
                    'bytes': i.bytes.hex(),
                    'mnemonic': i.mnemonic,
                    'op_str': i.op_str,
                    'is_target': (i.address + start) == offset
                })
                if len(context) >= context_size * 2 + 1:
                    break
            
            return context
        except:
            return []



@app.route('/pcap-scan')
@login_required
def pcap_scan_page():
    return render_template(
        'pcap_scan.html',
        os=os.uname().sysname,
        time=datetime.now().strftime("%H:%M:%S")
    )


@app.route('/upload-pcap-file', methods=['POST'])
@login_required
def upload_pcap_file():
    if 'pcapfile' not in request.files:
        flash("❌ No file uploaded", "danger")
        return redirect(url_for('pcap_scan_page'))

    file = request.files['pcapfile']
    if file.filename == '':
        flash("⚠ No file selected", "warning")
        return redirect(url_for('pcap_scan_page'))

    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE:
        flash("❌ File size exceeds maximum allowed (100MB)", "danger")
        return redirect(url_for('pcap_scan_page'))

    if file and allowed_file(file.filename) and file.filename.lower().endswith(('.pcap', '.pcapng')):
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        try:
            data = pcap.analyze_pcap(upload_path)
            
        except Exception as e:
            os.remove(upload_path)
            flash(f"❌ Error analyzing file: {str(e)}", "danger")
            return redirect(url_for('pcap_scan_page'))

        os.remove(upload_path)

        flash("✅ PCAP file uploaded and analyzed successfully!", "success")
        return render_template(
            "pcap_result.html",
            protocol_count=data["protocol_count"],
            packets=data["packets"],
            filename=filename
        )

    flash("❌ Invalid file type. Please upload a .pcap or .pcapng file.", "danger")
    return redirect(url_for('pcap_scan_page'))


def describe_packet(pkt):
    # Format timestamp nicely
    time_str = datetime.fromtimestamp(pkt['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
    
    # Human-readable protocol descriptions
    protocol_desc = {
        "TCP": "a reliable connection-oriented protocol (TCP)",
        "UDP": "a fast, connectionless protocol (UDP)",
        "ICMP": "a network diagnostic message (ICMP)",
        "HTTP": "web traffic (HTTP)",
        "DNS": "domain name system query (DNS)",
        # add more protocols as needed
    }
    
    proto = pkt.get('protocol', 'Unknown').upper()
    proto_text = protocol_desc.get(proto, f"protocol {proto}")
    
    src = pkt.get('src', 'Unknown source')
    dst = pkt.get('dst', 'Unknown destination')
    
    # Build descriptive sentence
    desc = (
        f"At {time_str}, a packet was sent from {src} to {dst} using {proto_text}."
    )
    
    # Optionally add extra info, e.g. ports or packet size if available
    if 'src_port' in pkt and 'dst_port' in pkt:
        desc += f" Source port: {pkt['src_port']}, destination port: {pkt['dst_port']}."
    if 'length' in pkt:
        desc += f" Packet size: {pkt['length']} bytes."
    
    return desc

@app.route('/perform-pcap-scan', methods=['POST'])
@login_required
def perform_pcap_scan():
    data = request.get_json()
    path = data.get('path')

    def generate():
        yield "data: 🔍 Starting PCAP analysis...\n\n"
        try:
            results = pcap.analyze_pcap(path)

            # Human-readable protocol count summary
            yield "data: 📊 Protocol summary:\n"
            for proto, count in results['protocol_count'].items():
                yield f"data: - {count} packets of protocol {proto}\n"
            yield "\n"

            # Human-readable packet details
            for pkt in results["packets"]:
                yield f"data: {describe_packet(pkt)}\n\n"

            yield "data: ✅ PCAP analysis completed\n\n"
        except Exception as e:
            yield f"data: ❌ Error during PCAP scan: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PEPPER_PATH = os.path.join(BASE_DIR, 'pepper.py')



@app.route('/pepper-analysis')
@login_required
def pepper_analysis_page():
    return render_template(
        'pepper_analysis.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/upload-pepper-file', methods=['POST'])
@login_required
def upload_pepper_file():
    if 'pepperfile' not in request.files:
        flash("❌ No file uploaded", "danger")
        return redirect(url_for('pepper_analysis_page'))

    file = request.files['pepperfile']
    if file.filename == '':
        flash("⚠ No file selected", "warning")
        return redirect(url_for('pepper_analysis_page'))

    # Check file size (limit to 100MB)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE:
        flash("❌ File size exceeds maximum allowed (100MB)", "danger")
        return redirect(url_for('pepper_analysis_page'))

    # Check file extension (only allow EXE for pepper analysis)
    if not (file and allowed_file(file.filename) and file.filename.lower().endswith('.exe')):
        flash("❌ Only .exe files are allowed for Pepper analysis", "danger")
        return redirect(url_for('pepper_analysis_page'))

    try:
        # Save the uploaded file
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)
        
        # Generate result filename with timestamp and random string for uniqueness
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_str = uuid.uuid4().hex[:6]
        result_filename = f"pepper_result_{timestamp}_{random_str}.txt"
        result_path = os.path.join(UPLOADS, result_filename)
        
        # Verify pepper.py exists
        if not os.path.exists(PEPPER_PATH):
            raise FileNotFoundError(f"Pepper analysis script not found at {PEPPER_PATH}")
        
        # Run pepper.py analysis on the uploaded file and save to result file
        with open(result_path, 'w') as result_file:
            result = subprocess.run(
                ['python', PEPPER_PATH, upload_path],
                stdout=result_file,
                stderr=subprocess.PIPE,
                text=True
            )
        
        # Remove the uploaded file after analysis
        os.remove(upload_path)
        
        if result.returncode != 0:
            os.remove(result_path)  # Clean up failed analysis
            flash(f"❌ Error analyzing file: {result.stderr}", "danger")
            return redirect(url_for('pepper_analysis_page'))

        # Store the result file path in session for download
        session['latest_pepper_result'] = result_filename
        
        # Read the result file for display
        with open(result_path, 'r') as f:
            clean_result = f.read()
        
        # Process the output for display
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_result = ansi_escape.sub('', clean_result)
        clean_result = re.sub(r'<\/?[^>]+>', '', clean_result)
        clean_result = re.sub(r'#//[^\s]+', '', clean_result)
        
        sections = []
        current_section = []
        for line in clean_result.split('\n'):
            if line.strip().startswith('=' * 20):
                if current_section:
                    sections.append('\n'.join(current_section))
                    current_section = []
            else:
                current_section.append(line)
        if current_section:
            sections.append('\n'.join(current_section))
        
        flash("✅ File uploaded and analyzed successfully!", "success")
        return render_template(
            "pepper_result.html",
            filename=filename,
            sections=sections,
            result_file=result_filename,
            os=get_os(),
            ip=get_lan_ip(),
            time=datetime.now().strftime("%H:%M:%S")
        )

    except Exception as e:
        # Clean up if something went wrong
        if os.path.exists(upload_path):
            os.remove(upload_path)
        if 'result_path' in locals() and os.path.exists(result_path):
            os.remove(result_path)
        flash(f"❌ Error analyzing file: {str(e)}", "danger")
        return redirect(url_for('pepper_analysis_page'))




@app.route('/perform-pepper-analysis', methods=['POST'])
@login_required
def perform_pepper_analysis():
    data = request.get_json()
    path = data.get('path')

    def generate():
        yield "data: 🔍 Starting Pepper analysis...\n\n"
        try:
            process = subprocess.Popen(
                ['python', PEPPER_PATH, path],  # Use absolute path here
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Stream output line by line
            for line in iter(process.stdout.readline, ''):
                yield f"data: {line.strip()}\n\n"

            # Check for errors
            stderr = process.stderr.read()
            if stderr:
                yield f"data: ❌ Error: {stderr}\n\n"

            yield "data: ✅ Pepper analysis completed\n\n"
        except Exception as e:
            yield f"data: ❌ Error during Pepper analysis: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/download-pepper-result')
@login_required
def download_pepper_result():
    if 'latest_pepper_result' not in session:
        flash("No analysis result available for download", "warning")
        return redirect(url_for('pepper_analysis_page'))
    
    result_filename = session['latest_pepper_result']
    result_path = os.path.join(UPLOADS, result_filename)
    
    if not os.path.exists(result_path):
        flash("Result file not found", "danger")
        return redirect(url_for('pepper_analysis_page'))
    
    try:
        return send_file(
            result_path,
            as_attachment=True,
            download_name=f"pepper_analysis_{datetime.now().strftime('%Y%m%d')}.txt",
            mimetype='text/plain'
        )
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "danger")
        return redirect(url_for('pepper_analysis_page'))


@app.route("/about")
def about():
    return render_template("about.html")
    

if __name__ == '__main__':
    app.config['UPLOAD_FOLDER'] = '/tmp/clamav_uploads'
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(threaded=True, host='0.0.0.0', port=5005, debug=True)