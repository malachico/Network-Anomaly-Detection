import socket

import dpkt
import numpy
from IPy import IP
from scipy.stats import multivariate_normal

import dal
import whitelist

HTTPS_PORT = 443

TOR_KPIS = ('num_of_sessions_io_avg', 'sessions_bandwidths', 'sessions_durations')

DDOS_KPIS = ('packets_count', 'io_ratios')

sessions_model = None

batches_model = None

packets_counter = 0

batch_start_time = None

# Batch of the current period
current_batch = None

# Time period for each batch
BATCH_PERIOD = None

# Size of batches_count
PERIODS_IN_HOUR = None

PERIODS_IN_DAY = None

ENDED_SESSION_TIME = 60

WHITELIST_TIME = 60 * 60

# Number of required batches before checking the traffic
TIME_TO_PARAMETERIZE = 0#24 * 60 * 60  # 1 Day

GATHERING_TIME = 0# 60*60#24 * 60 * 60 * 14  # 2 weeks

# Days backwards to remember batches
DAYS_REMEMBER = 30

# Number of batches to remember
NUMBER_OF_BATCHES_TO_REMEMBER = None

SESSIONS_EPSILON = min_not_tor_epsilon = max_tor_epsilon = 2.09003339968e-11

seconds_in_hour = 60 * 60

seconds_in_day = seconds_in_hour * 24


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

    # Average time for 5000 packets to arrive
    BATCH_PERIOD = 15#(duration / float(packets_counter)) * 5000.0

    print "BATCH_PERIOD : ", BATCH_PERIOD

    PERIODS_IN_HOUR = 60 * 60 / BATCH_PERIOD

    PERIODS_IN_DAY = 24 * PERIODS_IN_HOUR

    NUMBER_OF_BATCHES_TO_REMEMBER = int(PERIODS_IN_DAY * DAYS_REMEMBER)

    packets_counter = 0


def add_packet_to_batch(timestamp, packet):
    global current_batch
    current_batch.append((timestamp, packet))


def is_batch_time_over(timestamp):
    return timestamp - batch_start_time > BATCH_PERIOD


def reset_batch():
    global current_batch, batch_start_time

    current_batch = []
    batch_start_time += BATCH_PERIOD


def calc_io_ratio():
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


def is_https(ip_frame):
    # if not TCP return
    if ip_frame.p != dpkt.ip.IP_PROTO_TCP:
        return False

    tcp_frame = ip_frame.data

    # If it is not HTTPS return
    if HTTPS_PORT not in (tcp_frame.sport, tcp_frame.dport):
        return False

    return True


def extract_kpis(timestamp):
    """
    Parse sessions,
    Extract KPI's,
    Insert collected KPI's to kpi collection in DB

    KPI's:
    * number of packets
    * ingoing/outgoing packets ratio
    * session duration
    * session bandwidth

    :return:
    """
    global current_batch, batch_start_time, BATCH_PERIOD
    # KPIs
    # Insert sessions to DB
    https_packets = filter(lambda ip_frame: is_https(ip_frame[1]), current_batch)
    map(lambda ts_pckt: dal.upsert_session(ts_pckt[0], ts_pckt[1]), https_packets)

    # Clear all old sessions (timestamp is the time of the current packet) and extract their KPIs
    sessions_kpis = dal.remove_old_sessions_and_extract_kpis(timestamp)

    # Num of packets
    batch_kpis = {"timestamp": batch_start_time,
                  "packets_count": len(current_batch),
                  "io_ratios": calc_io_ratio()}

    # Insert KPIs tp DB
    dal.insert_kpis("batches_kpis", batch_kpis)

    if not sessions_kpis:
        return

    dal.insert_kpis("sessions_kpis", sessions_kpis)


def safe_log(num):
    try:
        return numpy.math.log(num, 2)
    except ValueError:
        return num


def build_models():
    global sessions_model, batches_model

    # Build sessions model
    kpis = dal.get_kpis('sessions_kpis')

    kpis = kpis.applymap(lambda x: safe_log(x))
    sessions_model = multivariate_normal(mean=kpis.mean(), cov=kpis.cov())

    # Build batches model
    kpis = dal.get_kpis('batches_kpis')

    batches_model = multivariate_normal(mean=kpis.mean(), cov=kpis.cov())


def check_tor_prob(sessions_kpis, suspected_sessions):
    global min_not_tor_epsilon, max_tor_epsilon

    for session, kpi in sessions_kpis.iteritems():
        # Check heuristics
        """
        1. heuristic:	If ToR (destination) has only 1 session
        2. heuristic:	If the destination speaks with the source only in one port
        3. heuristic:	If the source speaks with the destination only in one port

        """
        session = dict(session)

        # Check probability
        kpi_prob = sessions_model.pdf(kpi)

        # update_epsilons
        if kpi_prob > SESSIONS_EPSILON:
            min_not_tor_epsilon = min(kpi_prob, min_not_tor_epsilon)
            continue

        max_tor_epsilon = max(kpi_prob, max_tor_epsilon)

        dal.insert_prob(session, kpi, kpi_prob)

        # Check the stats are above average
        if kpi[0] > sessions_model.mean[0]:  # num_of_sessions_io_avg
            continue

        if kpi[1] < sessions_model.mean[1]:  # sessions_bandwidths
            continue

        if kpi[2] < sessions_model.mean[2]:  # sessions_durations
            continue

        # 1. heuristic:	If ToR (destination) has only 1 session
        # 2. heuristic:	If the destination speaks with the source only in one port
        if len(filter(lambda s: s['dest_ip'] == session['dest_ip'], suspected_sessions)) > 1:
            suspected_sessions = filter(lambda s: s['dest_ip'] != session['dest_ip'], suspected_sessions)
            continue

        # 3. heuristic:	If the source speaks with the destination only in one port
        if len(filter(lambda s: s['dest_ip'] == session['src_ip'] and s['src_ip'] == session['dest_ip'],
                      suspected_sessions)) > 1:
            suspected_sessions = filter(lambda s: s['dest_ip'] != session['dest_ip'], suspected_sessions)
            continue

        # Alert if found
        dal.alert(session, sessions_model.pdf(kpi))

    return (min_not_tor_epsilon + max_tor_epsilon) / 2


def check_ddos_prob():
    global current_batch
    # Check heuristics
    """
    1. heuristic:	If ToR (destination) has only 1 session
    2. heuristic:	If the destination speaks with the source only in one port
    3. heuristic:	If the source speaks with the destination only in one port

    """
    current_batch_kpis = (len(current_batch), calc_io_ratio())

    # Check the stats are above average
    if current_batch_kpis[0] < batches_model.mean[0]:  # batches_count
        return

    if current_batch_kpis[1] < batches_model.mean[1]:  # batches_ratios
        return

    # Check probability
    if batches_model.pdf(current_batch_kpis) > SESSIONS_EPSILON:
        return

    print "DDOS detected. batch start time : ", batch_start_time


def check_batch_probability():
    global SESSIONS_EPSILON
    sessions_kpis = dal.get_sessions_kpi()
    dal.insert_epsilon(batch_start_time, SESSIONS_EPSILON)
    SESSIONS_EPSILON = check_tor_prob(sessions_kpis, dal.get_all_sessions())
    # check_ddos_prob()


def preprocess_batch():
    whitelist.check_for_teamviewer()
