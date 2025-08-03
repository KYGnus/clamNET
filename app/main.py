from flask import Flask, render_template, request, Response, redirect, url_for, flash ,jsonify
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


app = Flask(__name__)
app.secret_key = config.SECRET_KEY  # Change this to a strong secret key

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Single admin user configuration
ADMIN_USERNAME = config.USERNAME
ADMIN_PASSWORD_HASH = generate_password_hash(f'{config.PASSWORD}')  # Change this password

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




import uuid
from flask import jsonify

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

@app.route('/scan_map')
def scan_map():
    network = request.args.get('network', '192.168.1.0/24')
    hosts = scan_network_topology(network)
    return render_template('network_map.html', hosts=hosts, network=network)






if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0', port=5005, debug=True)