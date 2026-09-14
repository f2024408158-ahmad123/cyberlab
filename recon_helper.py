import nmap

def scan_target(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')

    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                if info['state'] == 'open':
                    open_ports.append({
                        "port": port,
                        "proto": proto,
                        "service": info.get('name', ''),
                        "product": info.get('product', ''),
                        "version": info.get('version', '')
                    })
    return open_ports


if __name__ == "__main__":
    target = "192.168.56.101"
    print(f"Scanning {target} ...")
    results = scan_target(target)

    if not results:
        print("No open ports found.")
    else:
        print(f"Open ports on {target}:")
        for p in results:
            print(f"  {p['port']}/{p['proto']}  {p['service']}  {p['product']} {p['version']}")
