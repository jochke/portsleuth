import asyncio
import json
import os
import resource
import errno
from datetime import datetime, timezone

# Configuration
LOG_PATH = '/var/log/portsleuth/sentinel.jsonl'
SKIP_PORTS = {22}  # Ports to skip (e.g., SSH)
PORT_RANGE = range(1, 1025)  # Listen on ports 1–1024
FD_LIMIT = 5000  # Maximum file descriptors to request

async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    sock = writer.get_extra_info('sockname')
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z'
    log_record = {
        'ts_utc': ts,
        'src_ip': peer[0],
        'dst_ip': sock[0],
        'ip_proto': 'tcp',
        'dst_port': sock[1]
    }
    # Append to JSONL log
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(log_record) + '
')
    writer.close()
    await writer.wait_closed()

class UDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z'
        local = self.transport.get_extra_info('sockname')
        log_record = {
            'ts_utc': ts,
            'src_ip': addr[0],
            'dst_ip': local[0],
            'ip_proto': 'udp',
            'dst_port': local[1]
        }
        # Append to JSONL log
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(log_record) + '
')
        # Send dummy response
        self.transport.sendto(b'�', addr)

async def main():
    # Increase file descriptor limit
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, FD_LIMIT), hard))

    # Ensure log directory exists
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    loop = asyncio.get_running_loop()

    # Start TCP servers
    for port in PORT_RANGE:
        if port in SKIP_PORTS:
            continue
        try:
            await asyncio.start_server(handle_tcp, '0.0.0.0', port)
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                # Port already in use, skip
                continue
            raise

    # Start UDP endpoints
    for port in PORT_RANGE:
        if port in SKIP_PORTS:
            continue
        try:
            await loop.create_datagram_endpoint(
                UDPProtocol,
                local_addr=('0.0.0.0', port)
            )
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                continue
            raise

    # Run indefinitely
    await asyncio.Event().wait()

if __name__ == '__main__':
    asyncio.run(main())