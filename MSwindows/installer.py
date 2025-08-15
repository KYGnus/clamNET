import paramiko
import time
import os
from concurrent.futures import ThreadPoolExecutor
import concurrent



class ClamAVInstaller:
    def __init__(self, host, username, password, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.ssh = None
        self.os_type = None
        self.distro = None

    def connect(self):
        """Establish SSH connection and detect OS"""
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.host, port=self.port, 
                        username=self.username, password=self.password)
        
        # Detect OS and distro
        stdin, stdout, stderr = self.ssh.exec_command("uname -s")
        uname = stdout.read().decode().strip().lower()
        
        if 'linux' in uname:
            self.os_type = 'linux'
            # Detect Linux distribution
            stdin, stdout, stderr = self.ssh.exec_command("cat /etc/os-release | grep '^ID=' | cut -d'=' -f2")
            self.distro = stdout.read().decode().strip().lower().replace('"', '')
        else:
            # Try Windows detection
            stdin, stdout, stderr = self.ssh.exec_command("ver")
            windows_check = stdout.read().decode().strip()
            if "Microsoft" in windows_check:
                self.os_type = 'windows'
            else:
                self.os_type = 'unknown'

    def execute_command(self, command, wait=True):
        """Execute a command on the remote host"""
        stdin, stdout, stderr = self.ssh.exec_command(command)
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
                "sudo apt-get update",
                "sudo apt-get install -y clamav clamav-daemon"
            ]
        elif self.distro in ['centos', 'fedora', 'rocky', 'almalinux']:
            commands = [
                "sudo dnf install -y clamav clamd clamav-update || sudo yum install -y clamav clamd clamav-update"
            ]
        elif self.distro == 'opensuse':
            commands = [
                "sudo zypper -n install clamav"
            ]
        else:
            return False, "Unsupported Linux distribution"

        for cmd in commands:
            exit_status, _, error = self.execute_command(cmd)
            if exit_status != 0:
                return False, f"Installation failed: {error}"

        return True, "ClamAV installed successfully on Linux"

    def install_windows(self):
        """Install ClamAV on Windows"""
        try:
            # Download ClamAV
            download_cmd = (
                "powershell -Command \"Invoke-WebRequest "
                "-Uri 'https://www.clamav.net/downloads/production/clamav-1.4.3.win.x64.msi' "
                "-OutFile 'clamav-installer.msi'\""
            )
            exit_status, _, error = self.execute_command(download_cmd)
            if exit_status != 0:
                return False, f"Download failed: {error}"

            # Install MSI
            install_cmd = (
                "msiexec /i clamav-installer.msi /quiet /qn /norestart "
                "ADDLOCAL=ALL INSTALLDIR=\"C:\\Program Files\\ClamAV\""
            )
            exit_status, _, error = self.execute_command(install_cmd)
            if exit_status != 0:
                return False, f"Installation failed: {error}"

            # Wait for installation to complete
            time.sleep(30)

            # Configure ClamAV
            config_commands = [
                "mkdir \"C:\\Program Files\\ClamAV\\database\"",
                "copy \"C:\\Program Files\\ClamAV\\conf_examples\\clamd.conf.sample\" \"C:\\Program Files\\ClamAV\\clamd.conf\"",
                "copy \"C:\\Program Files\\ClamAV\\conf_examples\\freshclam.conf.sample\" \"C:\\Program Files\\ClamAV\\freshclam.conf\"",
                # Modify clamd.conf
                "(Get-Content \"C:\\Program Files\\ClamAV\\clamd.conf\") | " +
                "ForEach-Object { $_ -replace '^Example', '#Example' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\clamd.conf\"",
                "(Get-Content \"C:\\Program Files\\ClamAV\\clamd.conf\") | " +
                "ForEach-Object { $_ -replace '^#LogFile', 'LogFile' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\clamd.conf\"",
                "(Get-Content \"C:\\Program Files\\ClamAV\\clamd.conf\") | " +
                "ForEach-Object { $_ -replace '^#TCPSocket 3310', 'TCPSocket 3310' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\clamd.conf\"",
                "(Get-Content \"C:\\Program Files\\ClamAV\\clamd.conf\") | " +
                "ForEach-Object { $_ -replace '^#TCPAddr localhost', 'TCPAddr localhost' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\clamd.conf\"",
                # Modify freshclam.conf
                "(Get-Content \"C:\\Program Files\\ClamAV\\freshclam.conf\") | " +
                "ForEach-Object { $_ -replace '^Example', '#Example' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\freshclam.conf\"",
                "(Get-Content \"C:\\Program Files\\ClamAV\\freshclam.conf\") | " +
                "ForEach-Object { $_ -replace '^#UpdateLogFile', 'UpdateLogFile' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\freshclam.conf\"",
                "(Get-Content \"C:\\Program Files\\ClamAV\\freshclam.conf\") | " +
                "ForEach-Object { $_ -replace '^#DatabaseDirectory', 'DatabaseDirectory' } | " +
                "Set-Content \"C:\\Program Files\\ClamAV\\freshclam.conf\""
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
        
        # Test connection first
        _, stdout, _ = self.ssh.exec_command("echo 'Connection test'")
        if stdout.read().decode().strip() != "Connection test":
            return False, "SSH connection test failed"
            
        if self.os_type == 'linux':
            return self.install_linux()
        elif self.os_type == 'windows':
            return self.install_windows()
        else:
            return False, "Unsupported operating system"
            
    except paramiko.AuthenticationException:
        return False, "Authentication failed"
    except paramiko.SSHException as e:
        return False, f"SSH error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"
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

if __name__ == "__main__":
    # This is now just for testing - you can remove it or keep it as an example
    print("This script is meant to be imported and used by the web application")