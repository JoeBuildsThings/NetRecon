from flask import Flask, render_template, request
import requests
import socket

app = Flask(__name__)

def scan_ports(ip):
    ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080]
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports

@app.route('/', methods=['GET', 'POST'])
def index():
    data = None
    error = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if not target:
            error = "Enter an IP or domain."
        else:
            try:
                ip = socket.gethostbyname(target)
                res = requests.get(f"http://ip-api.com/json/{ip}").json()
                if res.get('status') == 'success':
                    data = res
                    data['scanned_ports'] = scan_ports(ip)
                else:
                    error = res.get('message', 'Invalid IP')
            except Exception as e:
                error = f"Error: {str(e)}"
    return render_template('index.html', data=data, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
