import asyncio
import json
import os
import resource
import errno
import signal
from datetime import datetime, timezone

# Configuration
LOG_PATH = '/var/log/portsleuth/sentinel.jsonl'
SKIP_PORTS = {22}               # Ports to skip (e.g., SSH)
PORT_RANGE = range(1, 1025)     # Listen on ports 1–1024
FD_LIMIT = 5000                 # Max file descriptors to request

async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    sock = writer.get_extra_info('sockname')
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z'
    record = {
        'ts_utc': ts,
        'src_ip': peer[0],
        'dst_ip': sock[0],
        'ip_proto': 'tcp',
        'dst_port': sock[1]
    }
    # Append JSONL log with newline
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(record) + '\n')
    writer.close()
    await writer.wait_closed()

class UDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z'
        local = self.transport.get_extra_info('sockname')
        record = {
            'ts_utc': ts,
            'src_ip': addr[0],
            'dst_ip': local[0],
            'ip_proto': 'udp',
            'dst_port': local[1]
        }
        # Append JSONL log with newline
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(record) + '\n')
        # Send dummy null-byte response
        self.transport.sendto(b'\x00', addr)

async def main():
    # Setup shutdown handler
    loop = asyncio.get_running_loop()
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s)))
    
    # Increase file descriptor limit
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, FD_LIMIT), hard))

    # Ensure log directory exists
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    # Track servers for clean shutdown
    tcp_servers = []
    udp_transports = []

    # Bind TCP servers
    for port in PORT_RANGE:
        if port in SKIP_PORTS:
            continue
        try:
            server = await asyncio.start_server(handle_tcp, '0.0.0.0', port)
            tcp_servers.append(server)
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                continue
            raise

    # Bind UDP endpoints
    for port in PORT_RANGE:
        if port in SKIP_PORTS:
            continue
        try:
            transport, _ = await loop.create_datagram_endpoint(
                UDPProtocol,
                local_addr=('0.0.0.0', port)
            )
            udp_transports.append(transport)
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                continue
            raise

    # Store servers for shutdown
    loop.servers = tcp_servers
    loop.transports = udp_transports
    
    # Run until signaled
    await asyncio.Event().wait()

async def shutdown(sig):
    """Cleanup resources and shutdown"""
    loop = asyncio.get_running_loop()
    
    # Close TCP servers
    for server in getattr(loop, 'servers', []):
        server.close()
        await server.wait_closed()
    
    # Close UDP transports
    for transport in getattr(loop, 'transports', []):
        transport.close()
    
    loop.stop()

if __name__ == '__main__':
    asyncio.run(main())
