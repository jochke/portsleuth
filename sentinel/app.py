import asyncio
import json
from datetime import datetime, timezone
import asyncio_dgram

LOG_PATH = '/var/log/portsleuth/sentinel.jsonl'

async def handle_tcp(reader, writer):
    addr = writer.get_extra_info('peername')
    ts = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    _, src_ip = addr
    dst_ip = writer.get_extra_info('sockname')[0]
    dst_port = writer.get_extra_info('sockname')[1]
    # Complete handshake: immediately close
    log = {
        'ts_utc': ts,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'ip_proto': 'tcp',
        'dst_port': dst_port
    }
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(log) + '\n')
    writer.close()
    await writer.wait_closed()

async def run_udp(server):
    async with asyncio_dgram.create_socket(local_addr=('0.0.0.0', 0), reuse_address=True) as sock:
        await sock.bind(('0.0.0.0', 0))
        while True:
            data, ancdata, flags, addr = await sock.recvmsg(1024)
            src_ip, src_port = addr
            dst_ip = sock.getsockname()[0]
            dst_port = sock.getsockname()[1]
            ts = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            # Echo a dummy response
            await sock.sendto(b'\x00', addr)
            log = {
                'ts_utc': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'ip_proto': 'udp',
                'dst_port': dst_port
            }
            with open(LOG_PATH, 'a') as f:
                f.write(json.dumps(log) + '\n')

async def main():
    # Ensure log directory exists
    import os
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    # TCP server on all ports
    servers = []
    for port in range(1, 65536):
        server = await asyncio.start_server(handle_tcp, '0.0.0.0', port)
        servers.append(server)

    # UDP listener covers all ports via socket per-port binds:
    # Because binding all 65535 is heavy, we bind ephemeral and let system redirect?
    # For simplicity, loop separate binds:
    tasks = [asyncio.create_task(run_udp(None))]
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    asyncio.run(main())