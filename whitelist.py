from socket import inet_ntoa

import dpkt
from IPy import IP

import common
import dal

TEAMVIEWER_PORT = 5938
TEAMVIEWER_IPS = IP('178.77.120.0/24')


def is_teamviewer(ip_frame):
    if ip_frame.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
        return False

    l4_frame = ip_frame.data

    if TEAMVIEWER_PORT != l4_frame.dport:
        return False

    dest_ip = inet_ntoa(ip_frame.dst)
    if dest_ip not in TEAMVIEWER_IPS:
        return False

    return True


def check_for_teamviewer():
    # Filter the teamviewer packets
    tv_frames = filter(lambda ip_frame: is_teamviewer(ip_frame[1]), common.current_batch)

    # Insert the ips which used the teamviewer to the whitelist in DB
    map(lambda frame: dal.upsert_whitelist(inet_ntoa(frame[1].src), frame[0]), tv_frames)
