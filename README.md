# tcp-proxy

Forwards TCP traffic as is from one peer to another, acting like a proxy. Supports data dumping and connections limit. Useful for debugging of unencrypted protocols, for bypassing firewall, for activity logging, for address alias. This project can be used as a base for more complex project that want to interfere between peers.

## Usage

```bash
env LISTEN_PORT=5000 FORWARD_PORT=1080 python3 main.py
```

```bash
env LISTEN_HOST=0.0.0.0 LISTEN_PORT=2000 FORWARD_HOST=192.168.0.1 FORWARD_PORT=80 python3 main.py
```

```bash
env LISTEN_PORT=80 FORWARD_HOST=google.com FORWARD_PORT=80 DUMP=1 DUMP_FLUSH=1 python3 main.py
```

## Installation

```bash
git clone https://github.com/Amaimersion/tcp-proxy.git
cd tcp-proxy
```

## Options

Pass them as environment variables.

- `LISTEN_HOST=127.0.0.1`: accept connections on this host
- `LISTEN_PORT=5000`: accept connections on this port
- `FORWARD_HOST=127.0.0.1`: forward connections to this host
- `FORWARD_PORT=1080`: forward connections to this port
- `LOG_LEVEL=20`: logging verbosity, `10` is debug, `20` is info, `30` is warning, `40` is error
- `IDLE_TIMEOUT=120`: close idle connections after this time, in seconds
- `MAX_CONNS=500`: maximum number of accepted connections that are being forwarded, note that setting more than 500 will likely result in [error](https://man7.org/linux/man-pages/man2/select.2.html#DESCRIPTION)
- `BACKLOG_CONNS=128`: maximum number of pending connections that are waiting to be accepted
- `RCV_BUF_SIZE=8192`: maximum number of bytes to read at once per each connection
- `SND_BUF_SIZE=8192`: maximum number of bytes to write at once per each connection
- `DUMP=`: dump connections data into file, pass any value to enable it
- `DUMP_FILE=dump.txt`: name of dump file
- `DUMP_FLUSH=`: write into file immediately instead of buffering small writes, pass any value to enable it

## Dump

Connection data is handled as raw bytes and logged as hexadecimal values. If initial data is unencrypted text, you can convert it into readable using any hex-to-string converter.

Example of dump when accessing `http://google.com` through SOCKS5 proxy like `curl -> tcp-proxy -> socks-proxy -> google`:

<details>
    <summary>dump.txt</summary>

    [1758883932593] [127.0.0.1:54570 -> 127.0.0.1:1080] [2 -> 3] [4] 05 02 00 01
    [1758883932594] [127.0.0.1:1080 -> 127.0.0.1:54570] [3 -> 2] [2] 05 00
    [1758883932722] [127.0.0.1:54570 -> 127.0.0.1:1080] [2 -> 3] [10] 05 01 00 01 d8 3a cf ee 00 50
    [1758883932724] [127.0.0.1:1080 -> 127.0.0.1:54570] [3 -> 2] [10] 05 00 00 01 d8 3a cf ee 00 50
    [1758883932724] [127.0.0.1:54570 -> 127.0.0.1:1080] [2 -> 3] [74] 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 67 6f 6f 67 6c 65 2e 63 6f 6d 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 63 75 72 6c 2f 38 2e 31 34 2e 31 0d 0a 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a
    [1758883932900] [127.0.0.1:1080 -> 127.0.0.1:54570] [3 -> 2] [773] 48 54 54 50 2f 31 2e 31 20 33 30 31 20 4d 6f 76 65 64 20 50 65 72 6d 61 6e 65 6e 74 6c 79 0d 0a 4c 6f 63 61 74 69 6f 6e 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 68 74 6d 6c 3b 20 63 68 61 72 73 65 74 3d 55 54 46 2d 38 0d 0a 43 6f 6e 74 65 6e 74 2d 53 65 63 75 72 69 74 79 2d 50 6f 6c 69 63 79 2d 52 65 70 6f 72 74 2d 4f 6e 6c 79 3a 20 6f 62 6a 65 63 74 2d 73 72 63 20 27 6e 6f 6e 65 27 3b 62 61 73 65 2d 75 72 69 20 27 73 65 6c 66 27 3b 73 63 72 69 70 74 2d 73 72 63 20 27 6e 6f 6e 63 65 2d 74 55 32 54 55 76 34 69 70 6a 4f 58 57 6e 34 65 77 63 50 4c 4d 41 27 20 27 73 74 72 69 63 74 2d 64 79 6e 61 6d 69 63 27 20 27 72 65 70 6f 72 74 2d 73 61 6d 70 6c 65 27 20 27 75 6e 73 61 66 65 2d 65 76 61 6c 27 20 27 75 6e 73 61 66 65 2d 69 6e 6c 69 6e 65 27 20 68 74 74 70 73 3a 20 68 74 74 70 3a 3b 72 65 70 6f 72 74 2d 75 72 69 20 68 74 74 70 73 3a 2f 2f 63 73 70 2e 77 69 74 68 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 73 70 2f 67 77 73 2f 6f 74 68 65 72 2d 68 70 0d 0a 44 61 74 65 3a 20 46 72 69 2c 20 32 36 20 53 65 70 20 32 30 32 35 20 31 30 3a 35 32 3a 32 32 20 47 4d 54 0d 0a 45 78 70 69 72 65 73 3a 20 53 75 6e 2c 20 32 36 20 4f 63 74 20 32 30 32 35 20 31 30 3a 35 32 3a 32 32 20 47 4d 54 0d 0a 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 70 75 62 6c 69 63 2c 20 6d 61 78 2d 61 67 65 3d 32 35 39 32 30 30 30 0d 0a 53 65 72 76 65 72 3a 20 67 77 73 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 32 31 39 0d 0a 58 2d 58 53 53 2d 50 72 6f 74 65 63 74 69 6f 6e 3a 20 30 0d 0a 58 2d 46 72 61 6d 65 2d 4f 70 74 69 6f 6e 73 3a 20 53 41 4d 45 4f 52 49 47 49 4e 0d 0a 0d 0a 3c 48 54 4d 4c 3e 3c 48 45 41 44 3e 3c 6d 65 74 61 20 68 74 74 70 2d 65 71 75 69 76 3d 22 63 6f 6e 74 65 6e 74 2d 74 79 70 65 22 20 63 6f 6e 74 65 6e 74 3d 22 74 65 78 74 2f 68 74 6d 6c 3b 63 68 61 72 73 65 74 3d 75 74 66 2d 38 22 3e 0a 3c 54 49 54 4c 45 3e 33 30 31 20 4d 6f 76 65 64 3c 2f 54 49 54 4c 45 3e 3c 2f 48 45 41 44 3e 3c 42 4f 44 59 3e 0a 3c 48 31 3e 33 30 31 20 4d 6f 76 65 64 3c 2f 48 31 3e 0a 54 68 65 20 64 6f 63 75 6d 65 6e 74 20 68 61 73 20 6d 6f 76 65 64 0a 3c 41 20 48 52 45 46 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 22 3e 68 65 72 65 3c 2f 41 3e 2e 0d 0a 3c 2f 42 4f 44 59 3e 3c 2f 48 54 4d 4c 3e 0d 0a
</details>

First 4 data exchanges are SOCKS5 protocol related. They initiate connection through SOCKS server. Last two lines are HTTP protocol related. They do HTTP request-response.

<details>
    <summary>HTTP request</summary>

    GET / HTTP/1.1
    Host: google.com
    User-Agent: curl/8.14.1
    Accept: */*
</details>

<details>
    <summary>HTTP response</summary>

    HTTP/1.1 301 Moved Permanently
    Location: http://www.google.com/
    Content-Type: text/html; charset=UTF-8
    Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-tU2TUv4ipjOXWn4ewcPLMA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
    Date: Fri, 26 Sep 2025 10:52:22 GMT
    Expires: Sun, 26 Oct 2025 10:52:22 GMT
    Cache-Control: public, max-age=2592000
    Server: gws
    Content-Length: 219
    X-XSS-Protection: 0
    X-Frame-Options: SAMEORIGIN

    <HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
    <TITLE>301 Moved</TITLE></HEAD><BODY>
    <H1>301 Moved</H1>
    The document has moved
    <A HREF="http://www.google.com/">here</A>.
    </BODY></HTML>
</details>
