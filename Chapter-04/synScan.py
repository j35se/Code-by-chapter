from scapy.all import IP, ICMP, TCP, sr1
import sys

def icmp_probe(ip):
    icmp_packet = IP(dst= ip)/ ICMP()
    resp_packet = sr1(icmp_packet, timeout = 10) #sr1 is to send and receive 1 ICMP Packet
    return resp_packet != None

def syn_scan(ip, port):
    syn_packet = IP(dst= ip)/TCP(dport=port, flags="S") #Creates a TCP packet with the SYN flag set
    resp_packet = sr1(syn_packet)
    if resp_packet.getlayer('TCP').flags == "SA":
        return resp_packet

if __name__ == "__main__":
    ip = sys.argv[1]
    port = int(sys.argv[2])
    if icmp_probe(ip):
        print("\nICMP Sucussful. Trying SYN-ACK\n")
        syn_ack_packet = syn_scan(ip, port)
        syn_ack_packet.show()
    else:
        print("ICMP Probe Failed")
