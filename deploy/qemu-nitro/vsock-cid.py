#!/usr/bin/env python3
"""Print the CID at which this machine reaches its own vsock listener on a port.

`vhost-device-vsock --forward-cid N` sends the enclave's connections to CID N on this machine.
The listeners here are of two kinds. heartbeat.py, nbd-stub.py and test-hooks.py bind every
CID. gvproxy binds the one the kernel reports as this machine's own, and only a connection to
that CID finds it:

- the loopback's, 1, when no other vsock transport is loaded: a workstation, a GitHub runner;
- the machine's own, when it is a VM with a vsock device, or 2 when it hosts vsock guests.

So the answer is asked for, not assumed: the kernel's CID first, then 1, and the first one a
connection to the port succeeds on. Run it once gvproxy is listening.

Usage: vsock-cid.py <port>
"""
import fcntl
import socket
import struct
import sys

port = int(sys.argv[1])
with open("/dev/vsock", "rb") as dev:
    request = socket.IOCTL_VM_SOCKETS_GET_LOCAL_CID
    own = struct.unpack("I", fcntl.ioctl(dev, request, bytes(4)))[0]

tried = []
for cid in dict.fromkeys([own, 1]):
    if cid == socket.VMADDR_CID_ANY:
        continue
    tried.append(cid)
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as conn:
        # A CID nothing here serves is another machine's: the connection leaves for the host
        # and is never answered.
        conn.settimeout(3)
        try:
            conn.connect((cid, port))
        except OSError:
            continue
    print(cid)
    sys.exit(0)

sys.exit(
    f"this machine does not reach its own vsock port {port} (tried CID "
    f"{', '.join(map(str, tried))}). With a listener there, that is the loopback transport "
    "missing: sudo modprobe vsock_loopback"
)
