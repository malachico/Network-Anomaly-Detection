import numpy
from IPy import IP
from pymongo import MongoClient
import pymongo

import common

g_db = None
ENDED_SESSION_TIME = 60


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

    2.	Average number of sessions per remote from outside - inside
    heuristic:	If ToR (destination) has only 1 session

    3.	Average session bandwidth:
    heuristic:	If the source and destination session bandwidth is vast


    4.	Average session duration:
    heuristic:	If the source and destination session duration is long

    5.	Number of sessions between each host in the net to each remote host:
    heuristic:	If the destination speaks with the source only in one port
    heuristic:	If the source speaks with the destination only in one port

    :type timestamp: time now
    :return:
    """

    # Get sessions which ended during the batch
    ended_sessions = list(g_db["sessions"].find({"timestamp": {"$lt": timestamp - ENDED_SESSION_TIME}}))

    # filter all internal sessions
    ended_sessions = filter(lambda session: IP(session['src_ip']).iptype() != IP(session['dest_ip']).iptype(),
                            ended_sessions)

    # Get the ended sessions from inside the network
    ended_io_sessions = filter(lambda s: IP(s['dest_ip']).iptype() == 'PUBLIC', ended_sessions)
    ended_oi_sessions = filter(lambda s: IP(s['dest_ip']).iptype() == 'PRIVATE', ended_sessions)

    if not ended_io_sessions:
        return

    # Get their IPs
    ended_io_ips = map(lambda s: s['src_ip'], ended_io_sessions)
    ended_oi_ips = map(lambda s: s['src_ip'], ended_oi_sessions)

    # Get all sessions from DB
    all_sessions = list(g_db["sessions"].find())

    # filter all internal sessions
    all_sessions = filter(lambda session: IP(session['src_ip']).iptype() != IP(session['dest_ip']).iptype(),
                          all_sessions)

    # ## Extract KPIs ## #
    # 1. Average number of sessions per host in the network from inside - outside
    num_of_sessions_io_list = map(lambda ip: len(filter(lambda s: s['src_ip'] == ip, all_sessions)), ended_io_ips)
    num_of_sessions_io_avg = numpy.mean(num_of_sessions_io_list)
    append_kpi("num_of_sessions_io_avg", num_of_sessions_io_avg)

    # 2. Average number of sessions per remote from outside - inside
    num_of_sessions_oi_list = map(lambda ip: len(filter(lambda s: s['src_ip'] == ip, all_sessions)), ended_oi_ips)
    num_of_sessions_oi_avg = numpy.mean(num_of_sessions_oi_list)
    append_kpi("num_of_sessions_oi_avg", num_of_sessions_oi_avg)

    # 3. Average session bandwidth:
    bandwidths = map(lambda session: session['n_bytes'], ended_sessions)
    append_kpi("sessions_bandwidths", numpy.mean(bandwidths))

    # 4. Average session duration:
    durations = map(lambda session: session['timestamp'] - session['start_time'], ended_sessions)
    append_kpi("sessions_durations", numpy.mean(durations))

    # For each ended session get number of session with each of other sessions
    # 5. Number of sessions between each host in the net to each remote host:
    n_sessions_between_2_hosts = []
    for session in ended_sessions:
        n_sessions = len(
            filter(lambda s: s['src_ip'] == session['src_ip'] and s['dest_ip'] == session['dest_ip'], all_sessions))
        n_sessions_between_2_hosts.append(n_sessions)

    n_sessions_between_2_hosts_avg = numpy.mean(n_sessions_between_2_hosts)
    append_kpi("n_sessions_between_2_hosts_avg", n_sessions_between_2_hosts_avg)

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
    2.	Number of sessions of the remote (destination) from outside - inside
    3.	Session bandwidth
    4.	Session duration
    5.	Number of sessions between the source and destination

    :param session: session to get KPIs for
    :param all_sessions: all current sessions
    """
    # Number of sessions of the host (source) in the local net to outside
    n_sessions_src_ip = len(filter(lambda s: s['src_ip'] == session['src_ip'], all_sessions))

    # Number of sessions of the remote (destination) from outside - inside
    n_sessions_dest_ip = len(filter(lambda s: s['dest_ip'] == session['dest_ip'], all_sessions))

    session_duration = session['timestamp'] - session['start_time']

    # in case the duration is 0, log is a problem
    session_duration = max(session_duration, 1)

    # Number of sessions between the source and destination
    n_sessions_src_dest = len(
        filter(lambda s: s['dest_ip'] == session['dest_ip'] and s['dest_ip'] == session['dest_ip'], all_sessions))

    # return tuple of the KPIs
    kpis = n_sessions_src_ip, n_sessions_dest_ip, session['n_bytes'], session_duration, n_sessions_src_dest

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


def get_kpis(kpis_names):
    kpis = []

    for kpi_name in kpis_names:
        data = g_db.kpi.find_one({kpi_name: {'$exists': 1}}, {'_id': 0})
        logged_data = map(lambda x: numpy.math.log(x, 2), data[kpi_name])
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
    return g_db.epsilon.find({}, {'_id': 0})
