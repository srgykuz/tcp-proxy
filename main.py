import os
import sys
import socket
import select
import logging


LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 5000))

FORWARD_HOST = os.getenv("FORWARD_HOST", "127.0.0.1")
FORWARD_PORT = int(os.getenv("FORWARD_PORT", 1080))

LOG_LEVEL = int(os.getenv("LOG_LEVEL", logging.INFO))


logging.basicConfig(stream=sys.stdout, level=LOG_LEVEL, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class Conn:
    def __init__(self, s: socket.socket):
        self.s = s

    def __str__(self):
        return f"{self.sockname()}#{self.fileno()}"

    def fileno(self):
        return self.s.fileno()

    def sockname(self):
        addr = ()

        try:
            addr = self.s.getsockname()
        except OSError:
            addr = ("", -1)

        return f"{addr[0]}:{addr[1]}"

    def peername(self):
        addr = ()

        try:
            addr = self.s.getpeername()
        except OSError:
            addr = ("", -1)

        return f"{addr[0]}:{addr[1]}"


class ConnState:
    read: list[Conn] = []
    write: list[Conn] = []
    ex: list[Conn] = []
    forward: dict[Conn, Conn] = {}


def main():
    state = ConnState()

    listen_conn = listen(LISTEN_HOST, LISTEN_PORT)
    state.read.append(listen_conn)
    logger.info(f"{LISTEN_HOST}:{LISTEN_PORT} -> {FORWARD_HOST}:{FORWARD_PORT}")

    while state.read:
        rlist, wlist, xlist = select.select(state.read, state.write, state.ex)

        for conn in rlist:
            if conn is listen_conn:
                accept(conn, state)
            else:
                read(conn, state)

        for conn in wlist:
            write(conn, state)

        for conn in xlist:
            catch(conn, state)

    logger.info("stopped")


def listen(host: str, port: int) -> Conn:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = (host, port)

    s.setblocking(False)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(addr)
    s.listen(128)

    c = Conn(s)

    return c


def connect(host: str, port: int) -> Conn:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = (host, port)

    s.connect(addr)
    s.setblocking(False)

    c = Conn(s)

    return c


def close(conn: Conn, state: ConnState):
    if conn.s.fileno() != -1:
        logger.debug(f"{conn}: closed")
        conn.s.close()

    lists = [state.read, state.write, state.ex]

    for l in lists:
        try:
            l.remove(conn)
        except ValueError:
            pass

    fwd_conn = state.forward.pop(conn, None)

    if fwd_conn:
        close(fwd_conn, state)


def accept(conn: Conn, state: ConnState):
    peer_s, _ = conn.s.accept()
    peer_conn = Conn(peer_s)
    state.read.append(peer_conn)
    state.ex.append(peer_conn)
    logger.debug(f"{peer_conn}: accepted from {peer_conn.peername()}")
    logger.info(f"{peer_conn.peername()} connected")

    fwd_conn: Conn = None

    try:
        fwd_conn = connect(FORWARD_HOST, FORWARD_PORT)
    except ConnectionRefusedError:
        logger.error("forward host is unreachable")
        close(peer_conn, state)
        return

    state.read.append(fwd_conn)
    state.ex.append(fwd_conn)
    logger.debug(f"{peer_conn}: connected to {fwd_conn}")

    state.forward[peer_conn] = fwd_conn
    state.forward[fwd_conn] = peer_conn
    logger.debug(f"{peer_conn.peername()} <--> {peer_conn.sockname()} <--> {fwd_conn.sockname()} <--> {fwd_conn.peername()}")


def read(conn: Conn, state: ConnState):
    data = bytes()

    try:
        data = conn.s.recv(1024)
    except Exception as e:
        logger.debug(f"{conn}: {e}")
        close(conn, state)
        return

    if data:
        logger.debug(f"{conn}: read {len(data)} bytes")
        logger.debug(f"{conn}: {data.hex(" ")}")
        logger.debug(f"{conn.peername()} -{len(data)}-> {conn.sockname()}")
    else:
        logger.info(f"{conn.peername()} disconnected")
        close(conn, state)
        return

    fwd_conn = state.forward.get(conn)

    if fwd_conn is None:
        logger.error(f"{conn}: nowhere to forward")
        close(conn, state)
        return

    try:
        fwd_conn.s.sendall(data)
    except Exception as e:
        logger.debug(f"{fwd_conn}: {e}")
        close(fwd_conn, state)
        return

    logger.debug(f"{conn}: forwarded to {fwd_conn}")


def write(conn: Conn, state: ConnState):
    pass


def catch(conn: Conn, state: ConnState):
    logger.error(f"{conn}: exceptional condition")
    close(conn, state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
