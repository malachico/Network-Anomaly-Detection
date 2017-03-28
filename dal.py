import numpy
import pymongo
from IPy import IP
from pymongo import MongoClient

import common

g_db = None
ENDED_SESSION_TIME = 60
WHITELIST_TIME = 7 * 60 * 60


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
def update_session_bytes(session, n_bytes):
    g_db["sessions"].update(get_session_id(session), {"$inc": {'n_bytes': n_bytes}})


def update_session_timestamp(session):
    g_db["sessions"].update(get_session_id(session), {"$set": {'timestamp': session['timestamp']}})


def update_session_duration(session):
    session_start_time = g_db.sessions.find_one(get_session_id(session))['start_time']
    g_db.sessions.update(get_session_id(session), {"$set": {'duration': session['timestamp'] - session_start_time}})


def is_session_exists(session):
    return g_db['sessions'].find_one(get_session_id(session)) is not None


def upsert_session(session):
    """
    Given a session - insert if not exist, update if exist
    :param session:
    :return: None
    """
    return g_db['sessions'].update(get_session_id(session), session, upsert=True)


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
    ended_sessions = filter(lambda s: timestamp - s['timestamp'] > ENDED_SESSION_TIME, all_sessions)

    # Get the ended sessions from inside the network
    ended_io_sessions = filter(lambda s: IP(s['dest_ip']).iptype() == 'PUBLIC', ended_sessions)

    if not ended_io_sessions:
        return

    # Get their IPs
    ended_io_ips = map(lambda s: s['src_ip'], ended_io_sessions)

    # ## Extract KPIs ## #
    # 1. Average number of sessions per host in the network from inside - outside
    num_of_sessions_io_list = map(lambda ip: len(filter(lambda s: s['src_ip'] == ip, all_sessions)), ended_io_ips)
    num_of_sessions_io_avg = numpy.mean(num_of_sessions_io_list)
    append_kpi("num_of_sessions_io_avg", num_of_sessions_io_avg)

    # 2. Average session bandwidth:
    bandwidths = map(lambda s: s['n_bytes'], ended_sessions)
    append_kpi("sessions_bandwidths", numpy.mean(bandwidths))

    # 3. Average session duration:
    durations = map(lambda s: s['timestamp'] - s['start_time'], ended_sessions)
    duration_mean = numpy.mean(durations)
    append_kpi("sessions_durations", max(duration_mean, 1))

    # Remove old sessions
    g_db["sessions"].remove({"timestamp": {"$lt": timestamp - ENDED_SESSION_TIME}}, multi=True)


def append_kpi(field, value):
    g_db.kpi.update({field: {"$exists": True}},
                    {'$push':
                        {field: {
                            '$each': [value],
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def get_all_kpis():
    kpi_dicts = list(g_db.kpi.find({}, {'_id': 0}))
    return {k: v for kpi_dict in kpi_dicts for k, v in kpi_dict.items()}


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


def draw_histogram(kpi_name, data):
    import matplotlib.pyplot as plt
    import math
    plt.hist(map(lambda x: math.log(x), data[kpi_name]), bins=50, label=kpi_name)
    plt.title(kpi_name)
    plt.show()


def safe_log(num):
    try:
        return numpy.math.log(num, 2)
    except ValueError:
        return num


def get_kpis(kpis_names):
    kpis = []

    for kpi_name in kpis_names:
        data = g_db.kpi.find_one({kpi_name: {'$exists': 1}}, {'_id': 0})
        logged_data = map(lambda x: safe_log(x), data[kpi_name])
        # draw_histogram(kpi_name, g_db.kpi.find_one({kpi_name: {'$exists': 1}}, {'_id': 0}))
        kpis.append(logged_data)

    return kpis


def insert_session_prob(session, prob, kpi):
    session = dict(session)
    session.update({'prob': prob, 'kpi': kpi})

    return g_db['epsilon'].update(get_session_id(session), session, upsert=True)


def drop_sessions():
    g_db.sessions.drop()


def get_epsilons():
    return list(g_db.epsilon.find({}, {'_id': 0}))


def drop_epsilons():
    return g_db.epsilon.drop()


def alert(session, prob):
    """
    Add alert to DB if not found yet
    :param prob: probability for session
    :param session: the session which created the alert
    :return:
    """
    doc_to_upsert = dict(session)
    doc_to_upsert.update({'prob': prob})

    # upsert the doc and check the results
    result = g_db['alerts'].update(get_session_id(session), doc_to_upsert, upsert=True)

    # If it is not the first time this session was reported, return
    if result['updatedExisting']:
        return

    print "ToR detected in session: ", session


def get_all_sessions():
    return list(g_db["sessions"].find({}, {'_id': 0}))


# Whitelist methods
def upsert_whitelist(ip, timestamp):
    # dict to insert to whitelist collection
    dict_to_upsert = {'ip': ip, 'timestamp': timestamp}

    g_db['whitelist'].update({'ip': ip}, dict_to_upsert, upsert=True)


def is_in_whitelist(ip, timestamp):
    # remove old whitelist tuples
    g_db["whitelist"].remove({"timestamp": {"$lt": timestamp - WHITELIST_TIME}}, multi=True)

    # Return True if such an IP exists
    return g_db['whitelist'].find_one({'ip': ip}) is not None
