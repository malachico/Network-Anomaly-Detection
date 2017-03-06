import socket

import dpkt
import numpy
from IPy import IP
from collections import defaultdict

import dal
import sessions_extractor

packets_counter = 0

batch_start_time = None

# Batch of the current period
current_batch = None

# probability critics for length of batch
BATCH_LEN_EPSILON = 0.01

# probability critics for rate in batch
RATE_EPSILON = 0.01

# Time period for each batch
BATCH_PERIOD = None

# Size of batches_count
PERIODS_IN_HOUR = None

PERIODS_IN_DAY = None

# Number of required batches before checking the traffic
TIME_TO_PARAMETERIZE = 1  # 24 * 60 * 60  # 1 Day

GATHERING_TIME = 24 * 60 * 60 * 14  # 2 weeks

# Days backwards to remember batches
DAYS_REMEMBER = 30

# Number of batches to remember
NUMBER_OF_BATCHES_TO_REMEMBER = None


def internal_traffic(ip_frame):
    src_ip = socket.inet_ntoa(ip_frame.src)
    dest_ip = socket.inet_ntoa(ip_frame.dst)

    return IP(src_ip).iptype() == IP(dest_ip).iptype()


def inside_outside_traffic(session):
    """
    :param session: session to check
    :return: True if the session is from local net to remote false otherwise
    """
    return IP(session['src_ip']).iptype() == 'PRIVATE' and IP(session['dest_ip']).iptype() == 'PUBLIC'


def filter_packet(packet):
    # Parse the input
    eth_frame = dpkt.ethernet.Ethernet(packet)

    # Check if IP
    if eth_frame.type != dpkt.ethernet.ETH_TYPE_IP:
        return False

    # If not IP return
    ip_frame = eth_frame.data

    # If the traffic is not incoming traffic - return
    if internal_traffic(ip_frame):
        return False

    return ip_frame


def count_packet():
    global packets_counter

    packets_counter += 1

    if packets_counter % 10000 == 0:
        print packets_counter


def parameterize(duration):
    global BATCH_PERIOD, PERIODS_IN_HOUR, PERIODS_IN_DAY, NUMBER_OF_BATCHES_TO_REMEMBER, packets_counter

    # Average time for 10000 packets to arrive
    # BATCH_PERIOD = (packets_counter / duration) * 10000.0
    BATCH_PERIOD = (packets_counter / duration) * 10

    PERIODS_IN_HOUR = 60 * 60 / BATCH_PERIOD

    PERIODS_IN_DAY = 24 * PERIODS_IN_HOUR

    NUMBER_OF_BATCHES_TO_REMEMBER = int(PERIODS_IN_DAY * DAYS_REMEMBER)

    packets_counter = 0


def add_packet_to_batch(timestamp, packet):
    global current_batch
    current_batch.append((timestamp, packet))


def batch_time_over(timestamp):
    return timestamp - batch_start_time > BATCH_PERIOD


def reset_batch():
    global current_batch, batch_start_time

    current_batch = []
    batch_start_time += BATCH_PERIOD


def calc_ioratio():
    global current_batch
    ingoing = 0
    outgoing = 0

    for ip_frame in current_batch:
        ip_frame = ip_frame[1]
        src_ip = socket.inet_ntoa(ip_frame.src)
        dest_ip = socket.inet_ntoa(ip_frame.dst)

        src_ip_type = IP(src_ip).iptype()
        dest_ip_type = IP(dest_ip).iptype()

        if src_ip_type == 'PUBLIC' and dest_ip_type == 'PRIVATE':
            ingoing += 1
        elif src_ip_type == 'PRIVATE' and dest_ip_type == 'PUBLIC':
            outgoing += 1

    if outgoing == 0:
        return 0

    return ingoing / float(outgoing)


def calc_batch_rate_std():
    """

    :return: the std of packets per second in the current batch
    """
    global current_batch

    packets_per_sec = defaultdict(int)

    for ts_pckt in current_batch:
        packets_per_sec[ts_pckt[0]] += 1

    return numpy.var(packets_per_sec.values())


def extract_kpis(timestamp):
    """
    Parse sessions,
    Extract KPI's,
    Insert collected KPI's to kpi collection in DB

    KPI's:
    * number of packets
    * rate variance in batch
    * ingoing/outgoing packets ratio
    * session duration
    * session bandwidth

    :return:
    """
    global current_batch, batch_start_time, BATCH_PERIOD

    # KPIs
    # Clear all old sessions (timestamp is the time of the current packet) and extract their KPIs
    dal.remove_old_sessions_and_extract_kpis(timestamp)

    # Num of packets
    dal.append_kpi("batches_count", len(current_batch))

    # Rate STD
    dal.append_kpi("batches_ratios", calc_batch_rate_std())

    # Ingoing - outgoing ratio
    dal.append_kpi("batches_ratios", calc_ioratio())

    # Insert sessions to DB
    map(lambda ts_pckt: sessions_extractor.handle_sessions(ts_pckt[0], ts_pckt[1]), current_batch)

    sessions_kpis = dal.get_sessions_kpi()


def build_model():
    # TODO
    return None
