# web_server.py
from http.server import HTTPServer, SimpleHTTPRequestHandler

def run_server(ip, port=8080):
    server_address = (ip, port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Starting server on {ip}:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 web_server.py <IP_ADDRESS>")
        sys.exit(1)
    run_server(sys.argv[1])
