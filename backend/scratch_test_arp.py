import asyncio
from app.scanner.engine import ScannerEngine
import logging

logging.basicConfig(level=logging.INFO)

async def test_arp():
    print("Testing ARP discovery...")
    engine = ScannerEngine(timeout=3)
    hosts = await engine.arp_discover("192.168.4.0/22")
    print(f"Discovered {len(hosts)} hosts.")

if __name__ == "__main__":
    asyncio.run(test_arp())
