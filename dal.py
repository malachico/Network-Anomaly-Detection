import dpkt
import numpy
import pymongo
from IPy import IP
from pymongo import MongoClient
import pandas as pd
import common
import socket

g_db = None


def get_session_id(session):
    """
    Given a session return its 5-tuple which represent the document ID of ToR session

    :param session:
    :return:
    """
    return {'src_ip': session['src_ip'], 'src_port': session['src_port'], 'dest_ip': session['dest_ip'],
            'dest_port': session['dest_port'], 'protocol': session['protocol']}


def init_db():
    global g_db

    # Create client
    client = MongoClient()

    # Create db connection
    g_db = client['ade']

    g_db.sessions.create_index(
        [("src_ip", pymongo.DESCENDING), ("src_port", pymongo.DESCENDING), ("dest_ip", pymongo.DESCENDING),
         ("dest_port", pymongo.DESCENDING), ("protocol", pymongo.DESCENDING)])


# ### Sessions handling ### #
def upsert_session(timestamp, ip_frame):
    """
    Given a session - insert if not exist, update if exist
    :param ip_frame:
    :param timestamp: timestamp of the session
    :return: None
    """

    l4_frame = ip_frame.data

    # Pack all the parameters in a dictionary
    packet_dict = {'src_ip': socket.inet_ntoa(ip_frame.src),
                   'src_port': l4_frame.sport,
                   'dest_ip': socket.inet_ntoa(ip_frame.dst),
                   'dest_port': l4_frame.dport,
                   'protocol': dpkt.ip.IP_PROTO_TCP,
                   'timestamp': timestamp
                   }

    g_db['sessions'].update(
        get_session_id(packet_dict),
        {
            "$set": packet_dict,
            "$inc": {'n_bytes': len(ip_frame)},
            "$setOnInsert": {'start_time': timestamp}
        },
        upsert=True
    )


# ### KPI handling ### #
def remove_old_sessions_and_extract_kpis(timestamp):
    """
    Remove sessions which are older than g_session_time and extract their KPI's
    Those are ToR heuristics, while host (source) ---------> (destination) ToR  in the net:
    1.  The host (source) has less than average sessions
    2.  If ToR (destination) has only MAX_TOR_RELAY_SESSIONS https sessions
    3.	If the source and destination session bandwidth is vast
    4.	If the destination speaks with the source only in one port
    5.	If the source speaks with the destination only in one port
    *ALERT*

    The KPI's:
    1.	Average number of sessions per host in the network from inside - outside
    heuristic:	The host (source) has less than average sessions

    2.	Average session bandwidth:
    heuristic:	If the source and destination session bandwidth is vast

    3.	Average session duration:
    heuristic:	If the source and destination session duration is long


    :type timestamp: time now
    :return:
    """

    # Get all sessions from DB
    all_sessions = get_all_sessions()

    # Get sessions which ended during the batch
    ended_sessions = filter(lambda s: timestamp - s['timestamp'] > common.ENDED_SESSION_TIME, all_sessions)

    if not ended_sessions:
        return

    g_db['ended_sessions'].insert_many(ended_sessions)

    # Get the ended sessions from inside the network
    ended_io_sessions = filter(lambda s: IP(s['dest_ip']).iptype() == 'PUBLIC', ended_sessions)

    if not ended_io_sessions:
        return

    # Get their IPs
    ended_io_ips = map(lambda s: s['src_ip'], ended_io_sessions)

    # ## Extract KPIs ## #
    # 1. Average number of sessions per host in the network from inside - outside
    num_of_sessions_io_list = map(lambda ip: len(filter(lambda s: s['src_ip'] == ip, all_sessions)), ended_io_ips)

    # 2. Average session bandwidth:
    bandwidths = map(lambda s: s['n_bytes'], ended_sessions)

    # 3. Average session duration:
    durations = map(lambda s: s['timestamp'] - s['start_time'], ended_sessions)

    sessions_kpis = {"num_of_sessions_io_avg": numpy.mean(num_of_sessions_io_list),
                     "sessions_bandwidths": numpy.mean(bandwidths),
                     "sessions_durations": max(numpy.mean(durations), 1),
                     "timestamp": timestamp}

    # Remove old sessions
    g_db["sessions"].remove({"timestamp": {"$lt": timestamp - common.ENDED_SESSION_TIME}}, multi=True)

    return sessions_kpis


def insert_kpis(collection, kpis):
    g_db[collection].insert_one(kpis)


def get_session_kpi(session, all_sessions):
    """
    For each session - if it is from local net to remote (inside to outside),
    extract the following KPI's:

    1.	Number of sessions of the host (source) in the local net to outside
    2.	Session bandwidth
    3.	Session duration

    :param session: session to get KPIs for
    :param all_sessions: all current sessions
    """
    # Number of sessions of the host (source) in the local net to outside
    n_sessions_src_ip = len(filter(lambda s: s['src_ip'] == session['src_ip'], all_sessions))

    # Session duration
    session_duration = session['timestamp'] - session['start_time']

    # in case the duration is 0, log is a problem
    session_duration = max(session_duration, 1)

    # return tuple of the KPIs
    kpis = n_sessions_src_ip, session['n_bytes'], session_duration,

    # log kpis
    return map(lambda kpi: numpy.math.log(kpi, 2), kpis)


def get_sessions_kpi():
    """
    :return: a dictionary of sessions as keys and tuples of their KPI's as values
    """
    sessions_kpis = {}

    all_sessions = list(g_db.sessions.find({}, {'_id': 0}))

    inside_out_sessions = filter(lambda s: common.inside_outside_traffic(s), all_sessions)

    for session in inside_out_sessions:
        sessions_kpis[tuple(session.items())] = get_session_kpi(session, all_sessions)

    return sessions_kpis


def get_kpis(collection):
    # get sorted by timestamp from mongo
    all_kpis = list(g_db[collection].find({}, {'_id': 0}).sort("timestamp", pymongo.DESCENDING))

    current_ts = all_kpis[0]['timestamp']
    same_hour = []

    for i in range(30):
        current_ts -= common.seconds_in_day
        same_hour += filter(lambda x: current_ts + common.seconds_in_hour > x['timestamp'] > current_ts, all_kpis)
        all_kpis = filter(lambda x: x['timestamp'] < current_ts, all_kpis)
 
    df = pd.DataFrame(same_hour)
    del df['timestamp']
    return df


# ################## Alert methods ################## #
def alert(session, prob):
    """
    Add alert to DB if not found yet
    If the session alerted is in whitelist mark it as whitelist and then insert to DB
    :param prob: probability for session
    :param session: the session which created the alert
    :return:
    """
    doc_to_upsert = dict(session)
    doc_to_upsert.update({'prob': prob})

    session['whitelist'] = False

    if is_in_whitelist(session['src_ip'], session['timestamp']):
        session['whitelist'] = True
        remove_from_whitelist(session['src_ip'])

    # upsert the doc and check the results
    result = g_db['alerts'].update(get_session_id(session), doc_to_upsert, upsert=True)

    # If it is not the first time this session was reported, return
    if result['updatedExisting']:
        return

    print "ToR detected in session: ", session


# ################## Whitelist methods ################## #
def upsert_whitelist(ip, timestamp):
    # dict to insert to whitelist collection
    dict_to_upsert = {'ip': ip, 'timestamp': timestamp}

    g_db['whitelist'].update({'ip': ip}, dict_to_upsert, upsert=True)


def is_in_whitelist(ip, timestamp):
    # remove old whitelist tuples
    g_db["whitelist"].remove({"timestamp": {"$lt": timestamp - common.WHITELIST_TIME}}, multi=True)

    # Return True if such an IP exists
    return g_db['whitelist'].find_one({'ip': ip}) is not None


def remove_from_whitelist(ip):
    g_db["whitelist"].remove({'ip': ip})


# ################## Epsilon methods ################## #
def get_epsilons():
    return list(g_db.epsilon.find({}, {'_id': 0}))


def drop_epsilons():
    return g_db.epsilon.drop()


# ################## debug methods ################## #
def drop_sessions():
    g_db.sessions.drop()


def get_all_sessions():
    return list(g_db["sessions"].find({}, {'_id': 0}))


def get_all_kpis():
    kpi_dicts = list(g_db.batches_kpis.find({}, {'_id': 0}))
    return {k: v for kpi_dict in kpi_dicts for k, v in kpi_dict.items()}
