import asyncio
import json
from datetime import datetime, timezone
import os

LOG_PATH = '/var/log/portsleuth/sentinel.jsonl'
SKIP_PORTS = {22}  # ports to skip binding

async def handle_tcp(reader, writer):
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
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    loop = asyncio.get_running_loop()

    # TCP listeners on all ports except those in SKIP_PORTS
    for port in range(1, 65536):
        if port in SKIP_PORTS:
            continue
        await asyncio.start_server(handle_tcp, '0.0.0.0', port)

    # UDP endpoints on all ports except those in SKIP_PORTS
    for port in range(1, 65536):
        if port in SKIP_PORTS:
            continue
        # Note: no reuse_address on UDP binds
        await loop.create_datagram_endpoint(
            UDPProtocol,
            local_addr=('0.0.0.0', port)
        )

    # Block forever
    await asyncio.Event().wait()

if __name__ == '__main__':
    asyncio.run(main())
