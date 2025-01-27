from flask import Flask, request
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import socket
import ssl

app = Flask(__name__)

class SecurityScanner:
    def __init__(self, url):
        self.url = url if url.startswith("http") else "http://" + url
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def scan(self):
        try:
            self.check_ssl_cert()
            self.check_security_headers()
            self.check_xss_vulnerabilities()
            self.check_sql_injection()
            self.check_open_ports()
            self.check_information_disclosure()
            return self.vulnerabilities
        except Exception as e:
            return [f"Error during scan: {str(e)}"]

    def check_ssl_cert(self):
        try:
            hostname = self.url.split("://")[-1].split("/")[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        self.vulnerabilities.append("Invalid SSL certificate")
        except Exception as e:
            self.vulnerabilities.append(f"SSL certificate verification failed: {str(e)}")

    def check_security_headers(self):
        try:
            response = self.session.get(self.url)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header - vulnerable to MITM attacks',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options - vulnerable to MIME-sniffing',
                'X-Frame-Options': 'Missing X-Frame-Options - vulnerable to clickjacking',
                'Content-Security-Policy': 'Missing CSP - vulnerable to XSS and injection attacks',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Referrer-Policy': 'Missing Referrer-Policy header',
                'Permissions-Policy': 'Missing Permissions-Policy header'
            }

            for header, message in security_headers.items():
                if header not in headers:
                    self.vulnerabilities.append(message)

            if 'Server' in headers and headers['Server'] != '':
                self.vulnerabilities.append(f"Server information disclosed: {headers['Server']}")

        except requests.exceptions.RequestException as e:
            self.vulnerabilities.append(f"Error checking headers: {str(e)}")

    def check_xss_vulnerabilities(self):
        try:
            response = self.session.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            test_payload = "<script>alert(1)</script>"
            params = {param: test_payload for param in self.extract_parameters()}
            
            if params:
                test_response = self.session.get(self.url, params=params)
                if test_payload in test_response.text:
                    self.vulnerabilities.append("Potential Reflected XSS vulnerability detected")

        except Exception as e:
            self.vulnerabilities.append(f"Error checking XSS: {str(e)}")

    def check_sql_injection(self):
        sql_patterns = ["'", "1' OR '1'='1", "1; DROP TABLE users"]
        
        try:
            for pattern in sql_patterns:
                params = {param: pattern for param in self.extract_parameters()}
                if params:
                    response = self.session.get(self.url, params=params)
                    sql_errors = [
                        "sql syntax", "mysql_fetch", "sqlite3", "ORA-", "PostgreSQL",
                    ]
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.vulnerabilities.append(f"Potential SQL Injection vulnerability detected")
                            break

        except Exception as e:
            self.vulnerabilities.append(f"Error checking SQL injection: {str(e)}")

    def check_open_ports(self):
        try:
            hostname = self.url.split("://")[-1].split("/")[0]
            common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389]
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    self.vulnerabilities.append(f"Open port detected: {port}")
                sock.close()

        except Exception as e:
            self.vulnerabilities.append(f"Error checking ports: {str(e)}")

    def check_information_disclosure(self):
        common_files = [
            '/robots.txt', '/.git/config', '/.env', '/phpinfo.php',
            '/wp-config.php', '/.htaccess', '/admin/', '/backup/',
        ]

        for file in common_files:
            try:
                url = urljoin(self.url, file)
                response = self.session.get(url)
                if response.status_code == 200:
                    self.vulnerabilities.append(f"Sensitive file/directory exposed: {file}")
            except:
                continue

    def extract_parameters(self):
        try:
            response = self.session.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            params = set()
            for form in soup.find_all('form'):
                for input_field in form.find_all(['input', 'textarea']):
                    if input_field.get('name'):
                        params.add(input_field['name'])
            if '?' in self.url:
                query_params = self.url.split('?')[1].split('&')
                for param in query_params:
                    if '=' in param:
                        params.add(param.split('=')[0])
            return params
        except:
            return set()

@app.route('/', methods=['GET', 'POST'])
def index():
    vulnerabilities = []
    if request.method == 'POST':
        url = request.form.get('url')
        scanner = SecurityScanner(url)
        vulnerabilities = scanner.scan()
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scanner</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f9; padding: 20px; }}
            h1 {{ color: #333; }}
            form {{ margin-bottom: 20px; }}
            input[type="text"] {{ width: 80%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 5px; }}
            button {{ padding: 10px 15px; color: #fff; background-color: #007BFF; border: none; border-radius: 5px; cursor: pointer; }}
            button:hover {{ background-color: #0056b3; }}
            #progress-bar {{ display: none; width: 100%; background-color: #ddd; margin-top: 10px; }}
            #progress-bar div {{ width: 0%; height: 20px; background-color: #4caf50; text-align: center; color: white; }}
            ul {{ list-style-type: none; padding: 0; }}
            li {{ background: #fff; margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
        </style>
        <script>
            function showProgressBar() {{
                const progressBar = document.getElementById("progress-bar");
                progressBar.style.display = "block";
                const progress = progressBar.firstElementChild;
                let width = 0;
                const interval = setInterval(() => {{
                    if (width >= 100) {{
                        clearInterval(interval);
                    }} else {{
                        width += 10;
                        progress.style.width = width + "%";
                        progress.innerText = width + "%";
                    }}
                }}, 300);
            }}
        </script>
    </head>
    <body>
        <h1>Security Scanner</h1>
        <form method="POST" onsubmit="showProgressBar()">
            <input type="text" name="url" placeholder="Enter URL" required />
            <button type="submit">Scan</button>
        </form>
        <div id="progress-bar">
            <div></div>
        </div>
        <h2>Vulnerabilities:</h2>
        <ul>
            {"".join([f"<li>{v}</li>" for v in vulnerabilities]) if vulnerabilities else "<li>No vulnerabilities found or scan incomplete.</li>"}
        </ul>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(debug=True)
