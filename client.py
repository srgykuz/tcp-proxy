import socket
import http.client


LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5007

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5678

TIMEOUT = 30
DEBUG_DATA = True


def main():
    try:
        listen()
    except KeyboardInterrupt:
        print("Interrupted")


def listen():
    conn_id = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((LISTEN_HOST, LISTEN_PORT))
        s.listen(1)

        print(f"Listening at {LISTEN_HOST}:{LISTEN_PORT}")

        while True:
            conn, addr = s.accept()
            conn_id += 1

            try:
                handle(conn_id, conn, addr)
            except TimeoutError:
                print(f"{conn_id}: timeout")
            except Exception as e:
                print(f"{conn_id}: {e}")
        
    print("Stopped")


def handle(conn_id: str, conn: socket.socket, addr: tuple):
    addr_s = f"{addr[0]}:{addr[1]}"

    print(f"{conn_id}: connected by {addr_s}")

    conn.settimeout(TIMEOUT)

    with conn:
        while True:
            data_req = conn.recv(1024)

            print(f"{conn_id}: req data length - {len(data_req)}")

            if DEBUG_DATA:
                print(f"{conn_id}: req data:\n{data_req}")

            if not data_req:
                break

            data_resp = forward(conn_id, data_req)

            print(f"{conn_id}: req forwarded")
            print(f"{conn_id}: resp data length - {len(data_resp)}")

            if DEBUG_DATA:
                print(f"{conn_id}: resp data:\n{data_resp}")

            conn.sendall(data_resp)

            print(f"{conn_id}: resp forwarded")

    print(f"{conn_id}: disconnected with {addr_s}")


def forward(conn_id: str, body: bytes) -> bytes:
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Length": len(body)
    }
    conn = http.client.HTTPConnection(SERVER_HOST, SERVER_PORT, timeout=TIMEOUT)

    conn.request("POST", f"/x/{conn_id}", body, headers)

    resp = conn.getresponse()
    data = b""

    if resp.status == 200:
        data = resp.read()
    else:
        raise Exception(f"HTTP {resp.status}")

    conn.close()

    return data


if __name__ == "__main__":
    main()
