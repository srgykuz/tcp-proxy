import socket
import http.server
from datetime import datetime


LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5678

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080

SOCKETS: dict[str, socket.socket] = {}
SOCKETS_TIMESTAMP: dict[str, datetime] = {}
SOCKET_LIFETIME = 60 * 2

TIMEOUT = 30
DEBUG_DATA = True


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_404()

    def do_POST(self):
        if not self.path.startswith("/x/"):
            self.send_404()
            return
        
        self.protocol_version = "HTTP/1.1"

        conn_id = self.path.strip("/x/")
        length = int(self.headers.get("Content-Length", 0))
        data_req = self.rfile.read(length)

        print(f"{conn_id}: req data length - {len(data_req)}")

        if DEBUG_DATA:
            print(f"{conn_id}: req data:\n{data_req}")

        if not (conn_id and data_req):
            self.send_response(400)
            self.end_headers()
            return
        
        clear_sockets()
        
        socket = reuse_socket(conn_id)
        data_resp = forward(socket, data_req)

        print(f"{conn_id}: resp data length - {len(data_resp)}")

        if DEBUG_DATA:
            print(f"{conn_id}: resp data:\n{data_resp}")

        self.send_response(200)
        self.send_header("Content-Length", len(data_resp))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()

        self.wfile.write(data_resp)

    def send_404(self):
        self.protocol_version = "HTTP/1.1"
        self.close_connection = True

        body = b"Not found\n"

        self.send_response(404)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", len(body))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def main():
    try:
        run()
    except KeyboardInterrupt:
        print("Interrupted")


def run():
    server = http.server.HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)

    print(f"Listening at http://{LISTEN_HOST}:{LISTEN_PORT}")

    server.serve_forever()


def reuse_socket(id: str) -> socket.socket:
    if id not in SOCKETS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.connect((PROXY_HOST, PROXY_PORT))
        s.settimeout(TIMEOUT)

        SOCKETS[id] = s
        SOCKETS_TIMESTAMP[id] = datetime.now()

    return SOCKETS[id]


def clear_sockets():
    now = datetime.now()
    clear = []

    for id, ts in SOCKETS_TIMESTAMP.items():
        delta = now - ts
        
        if delta.seconds > SOCKET_LIFETIME:
            clear.append(id)

    for id in clear:
        s = SOCKETS.pop(id, None)

        if s:
            s.close()

        del SOCKETS_TIMESTAMP[id]


def forward(s: socket.socket, body: bytes) -> bytes:
    s.sendall(body)
    resp = s.recv(1024)

    return resp


if __name__ == "__main__":
    main()
