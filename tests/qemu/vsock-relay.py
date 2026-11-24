#!/usr/bin/env python3
"""Carry the enclave's connection to gvproxy: a vsock port on this machine, to gvproxy's socket.

The enclave's gvforwarder dials the parent on vsock port 1024, and `vhost-device-vsock
--forward-cid 1` turns that into a vsock connection to this machine's loopback CID. gvproxy can
listen on vsock itself, but it binds the one CID the kernel reports as this machine's own, and
that is the loopback's only on some machines: where it is another, the enclave's heartbeat is
answered (heartbeat.py binds every CID), gvproxy is never found, and the runtime gives up with
"the enclave network never came up". Seen on a CI runner whose kernel reports CID 2.

So this listens instead, on every CID like the other listeners here, and passes each connection
to gvproxy's Unix socket, which serves the same `/connect`.

Usage: vsock-relay.py <port> <gvproxy's unix socket>
"""
import socket
import sys
import threading

port, path = int(sys.argv[1]), sys.argv[2]


def pump(src, dst):
    try:
        while data := src.recv(1 << 16):
            dst.sendall(data)
    except OSError:
        pass
    # Either side ending ends both: the other pump's recv returns, and it does the same.
    for end in (src, dst):
        try:
            end.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
srv.bind((socket.VMADDR_CID_ANY, port))
srv.listen(8)
print(f"vsock-relay: listening on vsock port {port}, for {path}", flush=True)
while True:
    conn, peer = srv.accept()
    print(f"vsock-relay: a connection from CID {peer[0]}", flush=True)
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(path)
    except OSError as err:
        print(f"vsock-relay: gvproxy is not answering on {path}: {err}", flush=True)
        conn.close()
        continue
    threading.Thread(target=pump, args=(conn, upstream), daemon=True).start()
    threading.Thread(target=pump, args=(upstream, conn), daemon=True).start()
