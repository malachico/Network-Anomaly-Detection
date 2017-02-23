import socket

import dpkt
from IPy import IP

import dal

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


def parse_packet(timestamp, packet):
    """
    extract KPIs we use for our engine from the packet

    :param timestamp: timestamp of the packet arrival
    :param packet:
    :return:
    """
    # Parse the input
    eth_frame = dpkt.ethernet.Ethernet(packet)
    packet_bytes_len = len(eth_frame)

    # If not IP return
    if eth_frame.type != dpkt.ethernet.ETH_TYPE_IP:
        return

    ip_frame = eth_frame.data

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
                    'start_time': timestamp
                    }

    # If we first time see this destination IP, add new list with the s to hash and return
    if dal.is_session_exists(https_packet['dest_ip']):
        dal.upsert_session(https_packet)
        return

    # Else, clear all old sessions (timestamp is the time of the current packet)
    dal.remove_old_sessions(https_packet['timestamp'])

    # Add session if not found yet in the list
    if not dal.is_session_exists(https_packet):
        dal.upsert_session(https_packet)
        return

    dal.update_session_bytes(https_packet, packet_bytes_len)

    dal.update_session_timestamp(https_packet)
