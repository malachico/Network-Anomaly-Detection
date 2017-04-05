import socket

import dpkt
from IPy import IP

import dal


def is_internal_traffic(src_ip, dest_ip):
    """
        :param src_ip:
        :param dest_ip:
        :return: True if the traffic is within the net
        """
    src_ip_type = IP(src_ip).iptype()
    dest_ip_type = IP(dest_ip).iptype()

    return src_ip_type == dest_ip_type


def handle_sessions(timestamp, ip_frame):
    packet_bytes_len = len(ip_frame)
    src_ip = socket.inet_ntoa(ip_frame.src)
    dest_ip = socket.inet_ntoa(ip_frame.dst)

    tcp_frame = ip_frame.data

    # Pack all the parameters in a dictionary
    https_packet = {'src_ip': src_ip,
                    'src_port': tcp_frame.sport,
                    'dest_ip': dest_ip,
                    'dest_port': tcp_frame.dport,
                    'protocol': dpkt.ip.IP_PROTO_TCP,
                    'n_bytes': packet_bytes_len,
                    }

    dal.upsert_session(https_packet, timestamp)
