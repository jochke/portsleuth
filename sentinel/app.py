import asyncio
import json
import os
import resource
import errno
import signal
import sys
from datetime import datetime, timezone

# Configuration
LOG_PATH = '/var/log/portsleuth/sentinel.json'  # Changed extension to json
SKIP_PORTS = {22}               # Ports to skip (e.g., SSH)
PORT_RANGE = range(80,85)     # Listen on ports 1–1024
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
    
    # Live console output with immediate flush
    print(f"[{ts}] TCP | {peer[0]}:{peer[1]} → {sock[1]} | Connection received", flush=True)
    
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
        
        # Live console output with immediate flush
        print(f"[{ts}] UDP | {addr[0]}:{addr[1]} → {local[1]} | Packet received, responding", flush=True)
        
        # Send dummy null-byte response
        self.transport.sendto(b'\x00', addr)

async def main():
    # Configure stdout to be unbuffered
    sys.stdout.reconfigure(line_buffering=True)
    
    print(f"Starting PortSleuth Sentinel, logging to {LOG_PATH}", flush=True)
    
    # Setup shutdown handler
    loop = asyncio.get_running_loop()
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s)))
    
    # Increase file descriptor limit
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, FD_LIMIT), hard))
    print(f"File descriptor limit set to {min(hard, FD_LIMIT)}", flush=True)

    # Ensure log directory exists
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    # Track servers for clean shutdown
    tcp_servers = []
    udp_transports = []
    tcp_count = 0
    udp_count = 0

    # Bind TCP servers
    for port in PORT_RANGE:
        if port in SKIP_PORTS:
            continue
        try:
            server = await asyncio.start_server(handle_tcp, '0.0.0.0', port)
            tcp_servers.append(server)
            tcp_count += 1
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
            udp_count += 1
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                continue
            raise

    print(f"Listening on {tcp_count} TCP ports and {udp_count} UDP ports", flush=True)
    print("PortSleuth Sentinel is running. Press Ctrl+C to stop.", flush=True)
    print("-" * 70, flush=True)
    
    # Store servers for shutdown
    loop.servers = tcp_servers
    loop.transports = udp_transports
    
    # Run until signaled
    await asyncio.Event().wait()

async def shutdown(sig):
    """Cleanup resources and shutdown"""
    print(f"Shutting down PortSleuth Sentinel (signal: {sig})...", flush=True)
    loop = asyncio.get_running_loop()
    
    # Close TCP servers
    for server in getattr(loop, 'servers', []):
        server.close()
        await server.wait_closed()
    
    # Close UDP transports
    for transport in getattr(loop, 'transports', []):
        transport.close()
    
    print("Shutdown complete.", flush=True)
    loop.stop()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user", flush=True)
        sys.exit(0)
