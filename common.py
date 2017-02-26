import socket

import dpkt
from IPy import IP

start_time = None

# Batch of the current period
current_batch = None

# Fix-sized queue, holds the number of incoming packets in each batch
batches_queue = None

# Fix-sized queue, holds variance of rate packets in each batch
rate_queue = None

# probability critics for length of batch
BATCH_LEN_EPSILON = 0.01

# probability critics for rate in batch
RATE_EPSILON = 0.01

# Time period for each batch
BATCH_PERIOD = 30

# Size of batches_count
PERIODS_IN_HOUR = None

PERIODS_IN_DAY = None

# Number of required batches before checking the traffic
TIME_TO_PARAMETERIZE = 24 * 60 * 60

TIME_TO_LEARN = 24 * 60 * 60 * 14

# Days backwards to remember batches
DAYS_REMEMBER = 30

# Number of batches to remember
NUMBER_OF_BATCHES_TO_REMEMBER = None


def ingoing_traffic(ip_frame):
    """
    Check it the traffic is from outside the net to inside

    :param ip_frame: frame to
    :return: True if the communication is from outside to internal network
    """
    src_ip = socket.inet_ntoa(ip_frame.src)
    dest_ip = socket.inet_ntoa(ip_frame.dst)

    src_ip_type = IP(src_ip).iptype()
    dest_ip_type = IP(dest_ip).iptype()

    return src_ip_type == 'PUBLIC' and dest_ip_type == 'PRIVATE'


def filter_ingoing_ip_traffic(packet):
    # Parse the input
    eth_frame = dpkt.ethernet.Ethernet(packet)

    # Check if IP
    if eth_frame.type != dpkt.ethernet.ETH_TYPE_IP:
        return

    # If not IP return
    ip_frame = eth_frame.data

    # If the traffic is not incoming traffic - return
    if not ingoing_traffic(ip_frame):
        return

    return ip_frame
