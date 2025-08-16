from flask import Flask, render_template, request, Response, redirect, url_for, flash, jsonify, send_file, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import platform
import subprocess
import socket
from datetime import datetime
import paramiko
import ipaddress
import concurrent.futures
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent.futures import ThreadPoolExecutor
import json
import time
import os
import re
import psutil
import yara
import hashlib
import magic
from collections import defaultdict
import pandas as pd
from werkzeug.utils import secure_filename
import uuid
from urllib.parse import unquote
import config
from concurrent.futures import as_completed



app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Windows-specific configuration
app.config['MAINDIR'] = os.path.join(os.getenv('APPDATA'), 'clamNET')
app.config['UPLOADDIR'] = os.path.join(app.config['MAINDIR'], 'uploads')
app.config['IOC_RULES_DIR'] = os.path.join(app.config['MAINDIR'], 'ioc_rules')
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'doc', 'docx', 'xls', 'md', 'conf',
                                  'xlsx', 'ppt', 'pptx', 'exe', 'dll', 'js', 'config',
                                  'vbs', 'ps1', 'zip', 'rar', '7z', 'jpg', 'jpeg', 
                                  'png', 'jfif', 'heic', 'pcap', 'pcapng'}



                                  
app.config['MAX_FILE_SIZE'] = 100 * 1024 * 1024  # 100MB
app.config['PEPPER_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pepper.py')

# Ensure directories exist
os.makedirs(app.config['MAINDIR'], exist_ok=True)
os.makedirs(app.config['UPLOADDIR'], exist_ok=True)
os.makedirs(app.config['IOC_RULES_DIR'], exist_ok=True)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User management
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id == config.USERNAME:
        return User(user_id)
    return None

# Helper functions
def get_lan_ip():
    """Get local IP address on Windows"""
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return '127.0.0.1'

def get_os():
    return platform.system()

def get_windows_version():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        product_name = winreg.QueryValueEx(key, "ProductName")[0]
        release_id = winreg.QueryValueEx(key, "ReleaseId")[0] if "ReleaseId" in [v[0] for v in winreg.EnumValue(key, 0)] else ""
        return f"{product_name} {release_id}"
    except:
        return platform.system()


def build_command(path):
    """Build Windows-specific command"""
    return [r"C:\Program Files\ClamAV\clamscan.exe", "--recursive", "--infected", path]

def humanize_bytes(num, suffix="B"):
    """Convert bytes to human-readable format"""
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f} P{suffix}"

app.jinja_env.filters['humanize_bytes'] = humanize_bytes

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Windows-specific ClamAV installer
class ClamAVInstaller:
    def __init__(self, host, username, password, port=22):
        if not host or not username or not password:
            raise ValueError("Missing required connection parameters")
            
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port)
        self.ssh = None
        self.sftp = None
        self.os_type = None
        self.connected = False
        
    def connect(self, timeout=30):
        """Establish SSH and SFTP connections"""
        if self.connected and self.ssh.get_transport().is_active():
            return True
            
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=timeout,
                banner_timeout=timeout+15,
                auth_timeout=timeout
            )
            self.sftp = self.ssh.open_sftp()
            self.connected = True
            return True
        except Exception as e:
            self.connected = False
            if self.sftp:
                self.sftp.close()
            if self.ssh:
                self.ssh.close()
            raise Exception(f"Connection failed: {str(e)}")

    def execute_command(self, command, wait=True):
        """Execute a command on the remote host"""
        stdin, stdout, stderr = self.ssh.exec_command(command)
        if wait:
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            return exit_status, output, error
        return None, None, None

    def detect_os(self):
        """Windows OS detection"""
        try:
            win_detection_cmds = [
                'ver',
                'systeminfo | findstr /B /C:"OS Name"',
                'powershell -Command "(Get-CimInstance Win32_OperatingSystem).Caption"'
            ]
            
            for cmd in win_detection_cmds:
                stdin, stdout, stderr = self.ssh.exec_command(cmd)
                output = stdout.read().decode().strip().lower()
                if "windows" in output or "microsoft" in output:
                    self.os_type = 'windows'
                    output_lower = output.lower()
                    if "windows 11" in output_lower:
                        self.distro = 'windows11'
                    elif "windows 10" in output_lower:
                        self.distro = 'windows10'
                    elif "server" in output_lower:
                        self.distro = 'windowsserver'
                    else:
                        self.distro = 'windows'
                    return True
            return False
        except Exception as e:
            print(f"OS detection error: {str(e)}")
            return False

    def install(self):
        """Main installation method"""
        try:
            self.connect()
            
            if not self.detect_os():
                return False, "Failed to detect Windows operating system"
            
            return self.install_windows()
                
        except Exception as e:
            return False, f"Connection/Installation error: {str(e)}"
        finally:
            if self.ssh:
                self.ssh.close()

    def transfer_file(self, local_path, remote_path):
        """Securely transfer a file to the remote host"""
        try:
            self.sftp.put(local_path, remote_path)
            return True, "File transferred successfully"
        except Exception as e:
            return False, f"File transfer failed: {str(e)}"
        
    def install_windows(self):
        """Install ClamAV on Windows with improved compatibility"""
        try:
            # Define possible installation paths
            possible_install_dirs = [
                "C:\\Program Files\\ClamAV",
                "C:\\Program Files (x86)\\ClamAV"
            ]
            
            # Transfer MSI file
            local_msi_path = config.LOCAL_INSTALL_FILE
            remote_msi_path = config.REMOTE_INSTALL_FILE
            success, message = self.transfer_file(local_msi_path, remote_msi_path)
            if not success:
                return False, message

            # Install with Windows Installer
            install_cmd = (
                f"msiexec /i {remote_msi_path} /quiet /qn /norestart "
                "ADDLOCAL=ALL INSTALLDIR=\"C:\\Program Files\\ClamAV\""
            )
            exit_status, _, error = self.execute_command(install_cmd)
            if exit_status != 0:
                return False, f"Installation failed: {error}"

            # Find where ClamAV was actually installed
            installed_path = None
            for path in possible_install_dirs:
                test_cmd = f'if exist "{path}" echo exists'
                _, output, _ = self.execute_command(test_cmd)
                if "exists" in output:
                    installed_path = path
                    break
            
            if not installed_path:
                return False, "Could not determine ClamAV installation location"

            # Configure ClamAV with version-specific adjustments
            config_commands = [
                f'mkdir "{installed_path}\\database"',
                f'copy "{installed_path}\\conf_examples\\clamd.conf.sample" "{installed_path}\\clamd.conf"',
                f'copy "{installed_path}\\conf_examples\\freshclam.conf.sample" "{installed_path}\\freshclam.conf"',
                f'(Get-Content "{installed_path}\\clamd.conf") | ForEach-Object {{ $_ -replace "^Example", "#Example" }} | Set-Content "{installed_path}\\clamd.conf"',
                # Add Windows Defender exclusion (for Server 2016+ and Win10 1709+)
                'powershell -Command "Add-MpPreference -ExclusionPath \"C:\\Program Files\\ClamAV\" -ErrorAction SilentlyContinue"',
                # Add firewall rule for freshclam updates
                'netsh advfirewall firewall add rule name="ClamAV Freshclam" dir=out action=allow program="C:\\Program Files\\ClamAV\\freshclam.exe" enable=yes'
            ]

            for cmd in config_commands:
                exit_status, _, error = self.execute_command(cmd)
                if exit_status != 0:
                    # Non-fatal error for some configuration items
                    continue

            # Transfer database file
            local_cvd_path = config.LOCAL_CVD_FILE
            remote_cvd_path = f"{installed_path}\\database\\daily.cvd"
            success, message = self.transfer_file(local_cvd_path, remote_cvd_path)
            if not success:
                return False, f"Failed to transfer daily.cvd: {message}"

            # Create scheduled task for updates
            task_cmd = (
                'schtasks /Create /TN "ClamAV Update" /TR "\'C:\\Program Files\\ClamAV\\freshclam.exe\'" '
                '/SC DAILY /RU SYSTEM /F'
            )
            self.execute_command(task_cmd)

            return True, f"ClamAV installed successfully to {installed_path}"

        except Exception as e:
            return False, f"Windows installation error: {str(e)}"
        finally:
            # Clean up installer file
            if hasattr(self, 'sftp') and self.sftp:
                try:
                    self.sftp.remove(remote_msi_path)
                except:
                    pass

    def update_database(self, timeout=300):
        """Update ClamAV virus databases on Windows"""
        try:
            self.connect()
            
            cmd = '"C:\\Program Files\\ClamAV\\freshclam.exe" --verbose'
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

            exit_status = chan.recv_exit_status()
            output_str = ''.join(output).strip()

            if exit_status != 0:
                return False, f"Update failed: {output_str}"
            return True, output_str

        except Exception as e:
            return False, f"Update error: {str(e)}"
        finally:
            if self.ssh:
                self.ssh.close()

# IOC Scanner
class IOCScanner:
    def __init__(self):
        self.yara_rules = self._load_yara_rules()
        self.ioc_database = self._load_ioc_database()
        
    def _load_yara_rules(self):
        """Load YARA rules from the rules directory"""
        rules = {}
        yara_dir = os.path.join(app.config['IOC_RULES_DIR'], 'yara')
        
        try:
            if not os.path.exists(yara_dir):
                os.makedirs(yara_dir, exist_ok=True)
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
        db_path = os.path.join(app.config['IOC_RULES_DIR'], 'ioc_database.json')
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

# Routes
@app.route('/')
@login_required
def index():
    """Main dashboard"""
    cpu_percent = psutil.cpu_percent(interval=0.5)
    ram_percent = psutil.virtual_memory().percent
    net_io = psutil.net_io_counters()

    return render_template(
        'main.html',
        os=get_windows_version() if get_os() == 'Windows' else get_os(),
        ip=get_lan_ip(),
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == config.USERNAME and check_password_hash(generate_password_hash(config.PASSWORD), password):
            user = User(username)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/scan')
@login_required
def scan_page():
    """Scan page"""
    return render_template(
        'scan.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/perform-scan')
@login_required
def scan():
    """Perform scan (local or remote)"""
    path = request.args.get("scan_path")
    path = unquote(path) if path else None
    remote_host = request.args.get("remote_host")
    username = request.args.get("remote_user")
    password = request.args.get("remote_pass")
    port = request.args.get("remote_port", "22")

    def generate():
        yield "data: 🔄 Starting scan...\n\n"
        try:
            if remote_host:
                # Remote scan via SSH
                try:
                    port_num = int(port)
                    if not 1 <= port_num <= 65535:
                        raise ValueError("Port out of range")
                    
                    yield f"data: 🔗 Connecting to remote host {remote_host}:{port}...\n\n"
                    
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(
                        hostname=remote_host,
                        port=port_num,
                        username=username,
                        password=password,
                        timeout=30,
                        banner_timeout=45,
                        auth_timeout=30
                    )
                    
                    # Windows scan
                    clamav_paths = [
                        r'C:\Program Files\ClamAV\clamscan.exe',
                        r'C:\Program Files (x86)\ClamAV\clamscan.exe'
                    ]
                    
                    found_path = None
                    for path_option in clamav_paths:
                        test_cmd = f'powershell -Command "Test-Path \'{path_option}\'"'
                        stdin, stdout, stderr = ssh.exec_command(test_cmd)
                        if "True" in stdout.read().decode():
                            found_path = path_option
                            break

                    if not found_path:
                        yield "data: ❌ ClamAV not found on remote host\n\n"
                        return

                    scan_path = path.replace('/', '\\')
                    if ' ' in scan_path and not (scan_path.startswith('"') and scan_path.endswith('"')):
                        scan_path = f'"{scan_path}"'

                    scan_cmd = f'"{found_path}" --infected --recursive --remove --verbose {scan_path}'
                    full_cmd = f'cmd /c "{scan_cmd}"'
                    
                    chan = ssh.get_transport().open_session()
                    chan.exec_command(full_cmd)
                    
                    # Read output line by line
                    start_time = time.time()
                    timeout = 300  # 5 minutes
                    
                    while True:
                        line = chan.makefile('r').readline()
                        if line:
                            yield f"data: {line.strip()}\n\n"
                        elif time.time() - start_time > timeout:
                            yield "data: ⏰ Timeout waiting for scan output\n\n"
                            break
                        elif chan.exit_status_ready():
                            break
                        else:
                            time.sleep(0.1)
                            
                    yield "data: ✅ Remote scan finished.\n\n"
                    ssh.close()
                except Exception as e:
                    yield f"data: ❌ Error: {str(e)}\n\n"
            else:
                # Local scan
                yield "data: 🔍 Starting local scan...\n\n"
                try:
                    process = subprocess.Popen(
                        build_command(path), 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.STDOUT,
                        bufsize=1,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    for line in iter(process.stdout.readline, b''):
                        yield f"data: {line.decode('utf-8', errors='replace').strip()}\n\n"
                        
                    process.stdout.close()
                    return_code = process.wait()
                    
                    if return_code == 0:
                        yield "data: ✅ Local scan finished successfully.\n\n"
                    elif return_code == 1:
                        yield "data: ⚠️ Local scan found infected files!\n\n"
                    else:
                        yield f"data: ⚠️ Local scan finished with return code {return_code}\n\n"
                except FileNotFoundError:
                    yield "data: ❌ ClamAV not found. Please install ClamAV first.\n\n"
                except Exception as e:
                    yield f"data: ❌ Error during local scan: {str(e)}\n\n"
        except Exception as e:
            yield f"data: ❌ Unexpected error: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/install')
@login_required
def install_page():
    """Installation page"""
    return render_template(
        'install.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/perform-install', methods=['POST'])
@login_required
def install():
    """Perform remote installation"""
    hosts = [h.strip() for h in request.form.get("install_hosts", "").split(',') if h.strip()]
    username = request.form.get("install_user", "")
    password = request.form.get("install_pass", "")
    port = request.form.get("install_port", "22")

    def generate():
        yield "data: 🔧 Starting ClamAV installation on remote hosts...\n\n"
        if not hosts:
            yield "data: ❌ No valid hosts provided\n\n"
            return
            
        try:
            # Validate port
            try:
                port_num = int(port)
                if not 1 <= port_num <= 65535:
                    raise ValueError("Port out of range")
            except ValueError as e:
                yield f"data: ❌ Invalid port number: {str(e)}\n\n"
                return
                
            yield f"data: ⚙️ Attempting to install on {len(hosts)} hosts using port {port}...\n\n"
            
            # Process hosts in parallel
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_host = {
                    executor.submit(
                        install_on_single_host,
                        host,
                        username,
                        password,
                        port_num
                    ): host for host in hosts
                }
                
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        success, message = future.result()
                        status = "✅" if success else "❌"
                        for line in message.split('\n'):
                            if line.strip():
                                yield f"data: {status} {host}: {line.strip()}\n\n"
                    except Exception as e:
                        yield f"data: ❌ {host} failed: {str(e)}\n\n"
                        continue
                    
            yield "data: 🏁 Installation process completed\n\n"
        except Exception as e:
            yield f"data: ❌ Global installation error: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

def install_on_single_host(host, username, password, port):
    """Install ClamAV on a single Windows host"""
    try:
        installer = ClamAVInstaller(host, username, password, port=port)
        return installer.install()
    except paramiko.AuthenticationException:
        return False, "Authentication failed"
    except paramiko.SSHException as e:
        return False, f"SSH error: {str(e)}"
    except socket.timeout:
        return False, "Connection timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"
    finally:
        if hasattr(installer, 'ssh') and installer.ssh:
            installer.ssh.close()

@app.route('/ioc-scan')
@login_required
def ioc_scan_page():
    """IOC scan page"""
    return render_template(
        'ioc_scan.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/upload-ioc-file', methods=['POST'])
@login_required
def upload_ioc_file():
    """Upload and scan file for IOCs"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > app.config['MAX_FILE_SIZE']:
        return jsonify({'success': False, 'message': 'File size exceeds maximum allowed (100MB)'}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOADDIR'], filename)
        file.save(upload_path)
        
        # Scan the file
        scanner = IOCScanner()
        results = scanner.scan_file(upload_path)
        
        # Clean up
        os.remove(upload_path)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    return jsonify({'success': False, 'message': 'Invalid file type'}), 400



@app.route('/update-remote-databases', methods=['POST'])
@login_required
def update_remote_databases():
    """Update database on remote hosts"""
    hosts = [h.strip() for h in request.form.get("update_hosts", "").split(',') if h.strip()]
    username = request.form.get("update_user", "")
    password = request.form.get("update_pass", "")
    port = request.form.get("update_port", "22")

    def generate():
        yield "data: 🔄 Starting database update on remote hosts...\n\n"
        
        if not hosts:
            yield "data: ❌ No valid hosts provided\n\n"
            return
            
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError("Port out of range")
                
            local_db_path = os.path.join(app.config['MAINDIR'], 'daily.cvd')
            if not os.path.exists(local_db_path):
                yield "data: ❌ No local database file found. Upload one first.\n\n"
                return
                
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_host = {
                    executor.submit(
                        update_host_database,
                        host,
                        username,
                        password,
                        port_num,
                        local_db_path
                    ): host for host in hosts
                }
                
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        success, message = future.result()
                        status = "✅" if success else "❌"
                        for line in message.split('\n'):
                            if line.strip():
                                yield f"data: {status} {host}: {line.strip()}\n\n"
                    except Exception as e:
                        yield f"data: ❌ {host} failed: {str(e)}\n\n"
                        
            yield "data: 🏁 Database update process completed\n\n"
        except Exception as e:
            yield f"data: ❌ Global update error: {str(e)}\n\n"

    return Response(generate(), mimetype='text/event-stream')

def update_host_database(host, username, password, port, local_db_path):
    """Update database on a single host"""
    try:
        installer = ClamAVInstaller(host, username, password, port)
        installer.connect()
        
        # Transfer the database file
        remote_path = "C:\\Program Files\\ClamAV\\database\\daily.cvd"
        success, message = installer.transfer_file(local_db_path, remote_path)
        if not success:
            return False, message
            
        return True, "Database updated successfully"
    except Exception as e:
        return False, str(e)
    finally:
        if installer.ssh:
            installer.ssh.close()



@app.route('/pepper-analysis')
@login_required
def pepper_analysis_page():
    """Pepper malware analysis page"""
    return render_template(
        'pepper_analysis.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/upload-pepper-file', methods=['POST'])
@login_required
def upload_pepper_file():
    """Upload file for Pepper analysis"""
    if 'pepperfile' not in request.files:
        flash("❌ No file uploaded", "danger")
        return redirect(url_for('pepper_analysis_page'))

    file = request.files['pepperfile']
    if file.filename == '':
        flash("⚠ No file selected", "warning")
        return redirect(url_for('pepper_analysis_page'))

    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > app.config['MAX_FILE_SIZE']:
        flash("❌ File size exceeds maximum allowed (100MB)", "danger")
        return redirect(url_for('pepper_analysis_page'))

    # Check file extension
    if not (file and allowed_file(file.filename) and file.filename.lower().endswith('.exe')):
        flash("❌ Only .exe files are allowed for Pepper analysis", "danger")
        return redirect(url_for('pepper_analysis_page'))

    try:
        # Save the uploaded file
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOADDIR'], filename)
        file.save(upload_path)
        
        # Generate result filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        result_filename = f"pepper_result_{timestamp}.txt"
        result_path = os.path.join(app.config['UPLOADDIR'], result_filename)
        
        # Verify pepper.py exists
        if not os.path.exists(app.config['PEPPER_PATH']):
            raise FileNotFoundError(f"Pepper analysis script not found at {app.config['PEPPER_PATH']}")
        
        # Run pepper.py analysis
        process = subprocess.Popen(
            ['python', app.config['PEPPER_PATH'], upload_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Wait for process to complete with timeout
        try:
            stdout, stderr = process.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            process.kill()
            raise Exception("Analysis timed out after 5 minutes")
        
        # Save results
        with open(result_path, 'w') as f:
            f.write(stderr if process.returncode != 0 else stdout)
        
        # Clean up uploaded file
        os.remove(upload_path)
        
        if process.returncode != 0:
            os.remove(result_path)
            flash(f"❌ Error analyzing file: {stderr}", "danger")
            return redirect(url_for('pepper_analysis_page'))

        # Store result in session
        session['latest_pepper_result'] = result_filename
        
        # Process output for display
        clean_result = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', stdout)
        clean_result = re.sub(r'<\/?[^>]+>', '', clean_result)
        
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
        # Clean up
        if 'upload_path' in locals() and os.path.exists(upload_path):
            os.remove(upload_path)
        if 'result_path' in locals() and os.path.exists(result_path):
            os.remove(result_path)
        flash(f"❌ Error analyzing file: {str(e)}", "danger")
        return redirect(url_for('pepper_analysis_page'))

@app.route('/download-pepper-result')
@login_required
def download_pepper_result():
    """Download Pepper analysis results"""
    if 'latest_pepper_result' not in session:
        flash("No analysis result available for download", "warning")
        return redirect(url_for('pepper_analysis_page'))
    
    result_filename = session['latest_pepper_result']
    result_path = os.path.join(app.config['UPLOADDIR'], result_filename)
    
    # Security checks
    if not os.path.exists(result_path):
        flash("Result file not found", "danger")
        return redirect(url_for('pepper_analysis_page'))
    
    if not result_path.startswith(app.config['UPLOADDIR']):
        flash("Invalid file path", "danger")
        return redirect(url_for('pepper_analysis_page'))
    
    try:
        # Generate safe download filename
        safe_filename = f"pepper_analysis_{datetime.now().strftime('%Y%m%d')}.txt"
        
        # Stream the file for download
        def generate():
            with open(result_path, 'rb') as f:
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    yield data
            # Clean up after download
            try:
                os.remove(result_path)
                session.pop('latest_pepper_result', None)
            except:
                pass
                
        response = Response(generate(), mimetype='text/plain')
        response.headers['Content-Disposition'] = f'attachment; filename={safe_filename}'
        return response
            
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "danger")
        return redirect(url_for('pepper_analysis_page'))

@app.route("/about")
def about():
    """About page"""
    return render_template("about.html")

if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0', port=5005, debug=True)