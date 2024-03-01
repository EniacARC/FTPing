from scapy.all import *

DST_IP = '127.0.0.1'


def establish_connection():
    syn_pkt = IP(dst=DST_IP) / ICMP() / Raw(b"Syn")
    syn_pkt.show()
    syn_ack_pkt = sr1(syn_pkt)
    syn_ack_pkt.show()
    if ICMP in syn_ack_pkt and Raw in syn_ack_pkt and syn_ack_pkt[Raw] == b'Syn Ack':
        send(IP(dst=DST_IP) / ICMP() / Raw(b"Ack"))


def main():
    establish_connection()
    pkt1 = IP(dst=DST_IP) / ICMP() / Raw(b"0@hello world!")
    pkt2 = IP(dst=DST_IP) / ICMP()
    t1 = sr1(pkt1)
    send(pkt2)


if __name__ == '__main__':
    main()
