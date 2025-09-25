import os
import sys
import socket
import select
import logging
import time


LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", 5000))

FORWARD_HOST = os.getenv("FORWARD_HOST", "127.0.0.1")
FORWARD_PORT = int(os.getenv("FORWARD_PORT", 1080))

LOG_LEVEL = int(os.getenv("LOG_LEVEL", logging.INFO))
IDLE_TIMEOUT = int(os.getenv("IDLE_TIMEOUT", 120))
MAX_CONNS = int(os.getenv("MAX_CONNS", 500))
RCV_BUF_SIZE = int(os.getenv("RCV_BUF_SIZE", 8192))


logging.basicConfig(stream=sys.stdout, level=LOG_LEVEL, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class Conn:
    def __init__(self, s: socket.socket):
        self.s = s
        self.last_active = time.time()
        self.is_listen = False

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
    forward: dict[Conn, Conn] = {}
    sndbuf: dict[Conn, bytes] = {}


def main():
    state = ConnState()

    try:
        run(state)
    except KeyboardInterrupt:
        print()

    conns = state.read + state.write

    for conn in conns:
        close(conn, state)


def run(state: ConnState):
    last_clear = time.time()
    clear_interval = 10

    listen_conn = listen(LISTEN_HOST, LISTEN_PORT)
    state.read.append(listen_conn)
    logger.info(f"{LISTEN_HOST}:{LISTEN_PORT} -> {FORWARD_HOST}:{FORWARD_PORT}")

    while state.read:
        rlist, wlist, xlist = select.select(state.read, state.write, state.read, clear_interval)

        for conn in rlist:
            if conn is listen_conn:
                accept(conn, state)
            else:
                read(conn, state)

        for conn in wlist:
            write(conn, state)

        for conn in xlist:
            catch(conn, state)

        if (time.time() - last_clear) > clear_interval:
            clear(state)
            last_clear = time.time()


def listen(host: str, port: int) -> Conn:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = (host, port)

    s.setblocking(False)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(addr)
    s.listen(128)

    c = Conn(s)
    c.is_listen = True

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

    lists = [state.read, state.write]

    for l in lists:
        try:
            l.remove(conn)
        except ValueError:
            pass

    state.sndbuf.pop(conn, None)

    fwd_conn = state.forward.pop(conn, None)

    if fwd_conn:
        close(fwd_conn, state)


def accept(conn: Conn, state: ConnState):
    peer_s: socket.socket = None

    try:
        peer_s, _ = conn.s.accept()
    except Exception as e:
        logger.error(f"listen host: {e.__class__.__name__}")
        logger.debug(e)
        return

    peer_conn = Conn(peer_s)

    if len(state.read) > MAX_CONNS * 2:
        logger.warning("listen host: maximum connections reached")
        close(peer_conn, state)
        return

    state.read.append(peer_conn)

    logger.debug(f"{peer_conn}: accepted {peer_conn.peername()}")
    logger.info(f"{peer_conn.peername()} connected")

    fwd_conn: Conn = None

    try:
        fwd_conn = connect(FORWARD_HOST, FORWARD_PORT)
    except ConnectionRefusedError:
        logger.error("forward host: unreachable")
        close(peer_conn, state)
        return
    except Exception as e:
        logger.error(f"forward host: {e.__class__.__name__}")
        logger.debug(e)
        close(peer_conn, state)
        return

    state.read.append(fwd_conn)

    state.forward[peer_conn] = fwd_conn
    state.forward[fwd_conn] = peer_conn
    state.sndbuf[peer_conn] = bytes()
    state.sndbuf[fwd_conn] = bytes()

    logger.debug(f"{peer_conn}: mapped {fwd_conn}")
    logger.debug(f"{peer_conn.peername()} <--> {peer_conn.sockname()} <--> {fwd_conn.sockname()} <--> {fwd_conn.peername()}")


def read(conn: Conn, state: ConnState):
    data = bytes()

    try:
        data = conn.s.recv(RCV_BUF_SIZE)
    except Exception as e:
        logger.error(f"{conn}: {e.__class__.__name__}")
        logger.debug(f"{conn}: {e}")
        close(conn, state)
        return

    conn.last_active = time.time()

    if data:
        logger.debug(f"{conn}: read {len(data)} bytes")
        logger.debug(f"{conn}: {data.hex(" ")}")
    else:
        logger.info(f"{conn.peername()} disconnected")
        close(conn, state)
        return

    fwd_conn = state.forward.get(conn)

    if fwd_conn is None:
        logger.error(f"{conn}: nowhere to forward")
        close(conn, state)
        return

    state.sndbuf[fwd_conn] += data

    if fwd_conn not in state.write:
        state.write.append(fwd_conn)


def write(conn: Conn, state: ConnState):
    try:
        state.write.remove(conn)
    except ValueError:
        return

    conn.last_active = time.time()
    data = state.sndbuf[conn]
    sent = 0

    try:
        sent = conn.s.send(data)
    except Exception as e:
        logger.error(f"{conn}: {e.__class__.__name__}")
        logger.debug(f"{conn}: {e}")
        close(conn, state)
        return

    state.sndbuf[conn] = data[sent:]

    if state.sndbuf[conn]:
        state.write.append(conn)

    logger.debug(f"{conn}: sent {sent}/{len(data)} bytes")


def catch(conn: Conn, state: ConnState):
    logger.error(f"{conn}: exceptional condition")
    close(conn, state)


def clear(state: ConnState):
    now = time.time()

    for conn in state.read:
        if conn.is_listen:
            continue

        if (now - conn.last_active) > IDLE_TIMEOUT:
            logger.info(f"{conn}: idle")
            close(conn, state)


if __name__ == "__main__":
    main()
