from flask import Flask, render_template, request, Response
import platform
import subprocess
import socket
from datetime import datetime
import paramiko

app = Flask(__name__)

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


@app.route('/')
def index():
    return render_template(
        'index.html',
        os=get_os(),
        ip=get_lan_ip(),
        time=datetime.now().strftime("%H:%M:%S")
    )

@app.route('/scan')
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

if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0' , port=8080)
