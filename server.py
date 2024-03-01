import re

from scapy.all import *


def recv_file(dst_ip):
    data = ''
    seq = 0
    while True:
        pkt = sniff(lfilter=lambda p: IP in p and p[IP].src == dst_ip and ICMP in p, count=1)[0]
        if not Raw in pkt:
            break  # all the file was sent
        elif not re.search(r'^[0-9]+@+', pkt[Raw].decode()):
            continue
        # each raw is: seq num@--data--
        # each ack is: ACK@seq num
        seq_num, buf = pkt[Raw].decode().split('@')
        if seq_num == seq + 1:
            data += buf
            seq = seq_num + len(buf) - 1
        else:
            if seq_num < seq:
                data = data[:seq_num]
        seq = seq_num + len(buf) - 1

        sr(IP(dst=dst_ip) / ICMP() / Raw(bytes(f"Ack@{seq_num}", encoding='utf-8')))
    return data


def establish_connection():
    syn_pkt = sniff(lfilter=lambda p: ICMP in p and Raw in p and p[Raw] == b'Syn', count=1)[0]
    syn_pkt.show()
    dst_ip = syn_pkt[IP].src
    syn_ack_pkt = IP(dst=dst_ip) / ICMP() / Raw(b"Syn Ack")
    est_pkt = sr1(syn_ack_pkt)
    return ICMP in p and Raw in p and p[Raw] == b'Ack', dst_ip


def main():
    established, dst_ip = establish_connection()
    if established:
        # now I know ip can begin building the file
        file1 = recv_file(dst_ip)


if __name__ == '__main__':
    main()
