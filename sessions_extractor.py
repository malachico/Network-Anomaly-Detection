import dpkt
from IPy import IP

import dal
import socket

HTTPS_PORT = 443


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

    if is_internal_traffic(src_ip, dest_ip):
        return

    # if not TCP return
    if ip_frame.p != dpkt.ip.IP_PROTO_TCP:
        return

    tcp_frame = ip_frame.data

    # If it is not HTTPS return
    if HTTPS_PORT not in (tcp_frame.sport, tcp_frame.dport):
        return

    # Pack all the parameters in a dictionary
    https_packet = {'src_ip': src_ip,
                    'src_port': tcp_frame.sport,
                    'dest_ip': dest_ip,
                    'dest_port': tcp_frame.dport,
                    'protocol': dpkt.ip.IP_PROTO_TCP,
                    'n_bytes': packet_bytes_len,
                    'timestamp': timestamp,
                    'start_time': timestamp,
                    }

    # If session is not found yet in the DB, upsert and return
    if not dal.is_session_exists(https_packet):
        dal.upsert_session(https_packet)
        return

    # If session is already exist, update its bytes duration and timestamp
    dal.update_session_bytes(https_packet, packet_bytes_len)

    dal.update_session_timestamp(https_packet)
