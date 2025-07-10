# 🛡️ clamNET

A cross-platform web-based frontend for scanning files and directories using **ClamAV**. Supports both **local** and **remote (via SSH)** scanning on Windows and Linux machines. Built with Python and Flask.

![ClamAV Web Scanner Screenshot](https://your-screenshot-link-if-available.com)

---

## ✨ Features

- 🌐 Web-based user interface
- 💻 Local scanning using ClamAV (Linux/Windows)
- 🔐 Remote scanning over SSH (Linux or Windows detection)
- 📡 Real-time streaming output using Server-Sent Events (SSE)
- 🧠 OS auto-detection
- 💬 Clean log-style output in the browser

---

## 🛠️ Requirements

- Python 3.7+
- Flask
- Paramiko (for SSH support)
- ClamAV installed:
  - Linux: accessible via `clamscan`
  - Windows: `C:\Program Files\ClamAV\clamscan.exe`

---

## 📦 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/clamav-web-scanner.git
   cd clamav-web-scanner
````

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   > Create a `requirements.txt` with:
   >
   > ```
   > flask
   > paramiko
   > ```

3. **Run the application**

   ```bash
   python main.py
   ```

4. **Access via browser**
   Open your browser and go to:
   [http://localhost:8080](http://localhost:8080)

---

## 🌍 Usage

### 🔍 Local Scan

* Enter a valid path on the host system (e.g., `/home/user/docs` or `C:\Users\YourName\Documents`)
* Leave SSH fields empty

### 🧑‍💻 Remote Scan (SSH)

* Fill in the SSH hostname, username, and password
* Enter the remote path to scan

---

## 📁 Project Structure

```
clamav-web-scanner/
├── main.py                # Main Flask app
├── templates/
│   └── index.html         # Frontend page
├── static/                # (optional for assets like CSS/JS)
└── README.md
```

---

## 🧪 Example Commands (Backend)

* **Local Scan (Linux)**

  ```
  clamscan --recursive --infected --verbose /home/user/
  ```

* **Local Scan (Windows)**

  ```
  "C:\Program Files\ClamAV\clamscan.exe" --recursive --infected --verbose C:\Users\
  ```

---

## ⚙️ Deployment (Optional)

To build a standalone binary using PyInstaller:

**mswindows**

```bash
pyinstaller --onefile --add-data "templates;templates" --add-data "static;static" main.py -n clamNET.exe
```

**Linux**

```
pyinstaller --onefile --add-data "templates:templates" --add-data "static:static" --noconsole -n claNET.linux main.py && rm -rvf build && cp dist/clamNET.linux . && rm -rvf dist && rm *.spec && echo "Linux Executable File is READY : clamNET.linux\nyou can run the Script with ./clamNET.linux"
```

