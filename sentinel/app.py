import asyncio
import json
from datetime import datetime, timezone
import os
import resource

LOG_PATH = '/var/log/portsleuth/sentinel.jsonl'
SKIP_PORTS = {22}  # Example: skip SSH if desired
PORT_RANGE = range(1, 1025)  # only first 1024 ports

async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    sock = writer.get_extra_info('sockname')
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z'
    log = {
        'ts_utc': ts,
        'src_ip': peer[0],
        'dst_ip': sock[0],
        'ip_proto': 'tcp',
        'dst_port': sock[1]
    }
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(log) + '\n')
    writer.close()
    await writer.wait_closed()

class UDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + 'Z'
        local = self.transport.get_extra_info('sockname')
        log = {
            'ts_utc': ts,
            'src_ip': addr[0],
            'dst_ip': local[0],
            'ip_proto': 'udp',
            'dst_port': local[1]
        }
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(log) + '\n')
        self.transport.sendto(b'\x00', addr)

async def main():
    # Optionally bump file descriptor limit
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 5000), hard))

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    loop = asyncio.get_running_loop()

    # TCP listeners on selected ports
    for port in PORT_RANGE:
        if port in SKIP_PORTS:
            continue
        await asyncio.start_server(handle_tcp, '0.0.0.0', port)

    # UDP endpoints on selected ports
    for port in PORT_RANGE:
        if port in SKIP_PORTS:
            continue
        await loop.create_datagram_endpoint(
            UDPProtocol,
            local_addr=('0.0.0.0', port)
        )

    # Block forever
    await asyncio.Event().wait()

if __name__ == '__main__':
    asyncio.run(main())