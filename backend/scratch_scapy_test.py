
import sys
from scapy.all import ARP, Ether, srp, conf

def test_scapy():
    print("Testing Scapy permissions...")
    try:
        # Try a simple ARP request for the gateway or local net
        # We just want to see if it throws a PermissionError
        conf.verb = 0
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="127.0.0.1"), timeout=1, retry=0)
        print("Scapy test: SUCCESS (Network access OK)")
    except PermissionError:
        print("Scapy test: FAILED (Permission Denied - Run as Administrator)")
        sys.exit(1)
    except Exception as e:
        print(f"Scapy test: FAILED (Unexpected error: {e})")
        sys.exit(1)

if __name__ == "__main__":
    test_scapy()
