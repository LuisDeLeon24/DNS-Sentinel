from scapy.all import sniff, DNS, DNSQR
import sys

def djb2_update(h, c):
    """Update DJB2 hash with one byte"""
    return (((h << 5) + h) + c) & 0xFFFFFFFF

def hash_dns_wire_format(qname_bytes):
    """
    Hash QNAME in wire format (like eBPF does)
    Format: [len]label[len]label...[0]
    Example: www.google.com = [3]www[6]google[3]com[0]
    """
    h = 5381
    labels = qname_bytes.split(b'.')
    
    for label in labels:
        for byte in label:
            h = djb2_update(h, byte)
        h = djb2_update(h, ord('.'))
    
    return h

def process_dns_packet(packet):
    """Process DNS packet and extract QNAME"""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            qname = packet[DNSQR].qname
            
            if isinstance(qname, bytes):
                qname_str = qname.decode('utf-8', errors='ignore')
            else:
                qname_str = str(qname)
            
            if qname_str.endswith('.'):
                qname_str = qname_str[:-1]
            
            qname_bytes = qname_str.encode('utf-8')
            
            h = hash_dns_wire_format(qname_bytes)
            
            with open('/tmp/dns_domains.txt', 'a') as f:
                f.write(f"{h} {qname_str}\n")
            
            print(f"[+] {qname_str} -> {h}")
        except Exception as e:
            print(f"[!] Error processing packet: {e}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        print("Example: sudo python3 dns_sniffer.py enp0s3")
        sys.exit(1)
    
    iface = sys.argv[1]
    
    open('/tmp/dns_domains.txt', 'w').close()
    
    print(f"[*] Capturing DNS on {iface}...")
    print(f"[*] Writing to /tmp/dns_domains.txt")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        sniff(iface=iface, filter="udp port 53", prn=process_dns_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopped")
    except PermissionError:
        print("[!] Error: You need to run with sudo")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
