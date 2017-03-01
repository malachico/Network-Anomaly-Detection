import numpy
from IPy import IP
from pymongo import MongoClient
import common

g_db = None
ENDED_SESSION_TIME = 3 * 60


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


def is_session_exists(session):
    return g_db['sessions'].find_one(get_session_id(session)) is not None


def upsert_session(session):
    """
    Given a session - insert if not exist, update if exist
    :param session:
    :return: None
    """
    return g_db['sessions'].update(get_session_id(session), session, upsert=True)


def remove_old_sessions_and_extract_kpis(timestamp):
    """
    Remove sessions which are older than g_session_time and extract their KPI's
    Those are ToR heuristics, while ToR (source) ---------> (destination) host in the net:
    Those are ToR heuristics, while host (source) ---------> (destination) ToR  in the net:
    1.       The host (source) has less than average sessions
    2.       If ToR (destination) has only MAX_TOR_RELAY_SESSIONS https sessions
    3.       If the source and destination session bandwidth is vast
    4.       If the destination speaks with the source only in one port
    5.       If the source speaks with the destination only in one port
    6.       If the source and destination session duration is long
    *ALERT*
     
    The KPI’s:
    1.	Average number of sessions per host in the network from inside – outside
    a.	The host (source) has less than average sessions

    2.	Average number of sessions per remote from outside – inside
    a.	If ToR (destination) has only 1 session

    3.	Average session bandwidth:
    a.	If the source and destination session bandwidth is vast

    4.	Average session duration:
    a.	If the source and destination session duration is long

    5.	Number of sessions between each host in the net to each remote host:
    a.	If the destination speaks with the source only in one port

    6.	Number of sessions between each host in the net to each remote host:
    a.	If the source speaks with the destination only in one port

    :type timestamp: time now
    :return:
    """
    # Get sessions which ended during the batch
    ended_sessions = list(g_db["sessions"].find({"timestamp": {"$lt": timestamp - ENDED_SESSION_TIME}}))

    # filter all internal sessions
    ended_sessions = map(lambda session: IP(session['src_ip']).iptype() != IP(session['dest_ip']).iptype(),
                         ended_sessions)

    # Get the ended sessions from inside the network
    ended_local_sessions = map(lambda s: IP(s['dest_ip']).iptype() == 'PRIVATE', ended_sessions)
    ended_remote_sessions = map(lambda s: IP(s['dest_ip']).iptype() == 'PUBLIC', ended_sessions)

    # Get their IPs
    ended_local_ips = map(lambda s: s['dest_ip'], ended_local_sessions)
    ended_remote_ips = map(lambda s: s['dest_ip'], ended_remote_sessions)

    if not ended_local_sessions:
        append_bandwidths(0)
        append_durations(0)
        return

    # Get all sessions from DB
    all_sessions = list(g_db["sessions"].find())

    # filter all internal sessions
    all_sessions = map(lambda session: IP(session['src_ip']).iptype() != IP(session['dest_ip']).iptype(), all_sessions)

    # ## Extrack KPIs ## #
    # 1. Average number of sessions per host in the network from inside – outside
    num_of_sessions_io_list = map(lambda ip: len(filter(lambda s: s['src_ip'] == ip, all_sessions)), ended_local_ips)
    num_of_sessions_io_avg = numpy.mean(num_of_sessions_io_list)

    # 2. Average number of sessions per remote from outside – inside
    num_of_sessions_oi_list = map(lambda ip: len(filter(lambda s: s['src_ip'] == ip, all_sessions)), ended_local_ips)
    num_of_sessions_oi_avg = numpy.mean(num_of_sessions_oi_list)

    # 3. Average session bandwidth:
    bandwidths = map(lambda session: session['n_bytes'], ended_sessions)

    # 4. Average session duration:
    durations = map(lambda session: session['timestamp'] - session['start_time'], ended_sessions)

    # For each ended session get number of session with each of other sessions
    # 5. Number of sessions between each host in the net to each remote host:
    all_remote_ips = map(lambda s: IP(s['src_ip']).iptype() == 'PUBLIC', all_sessions)
    n_sessions_between_2_hosts = []
    for local_ip in ended_local_ips:
        for remote_ip in all_remote_ips:
            sessions = map(lambda s: local_ip in (s['src_ip'], s['dest_ip']) and remote_ip in (s['src_ip'], s['dest_ip']), all_sessions)
            if sessions:
                n_sessions_between_2_hosts.append(len(sessions))

    n_sessions_between_2_hosts_avg = numpy.mean(n_sessions_between_2_hosts)


    append_bandwidths(bandwidths)
    append_durations(durations)

    g_db["sessions"].remove({"timestamp": {"$lt": timestamp - ENDED_SESSION_TIME}}, multi=True)


def update_session_bytes(session, n_bytes):
    g_db["sessions"].update(get_session_id(session), {"$inc": {'n_bytes': n_bytes}})


def update_session_timestamp(session):
    g_db["sessions"].update(get_session_id(session), {"$set": {'timestamp': session['timestamp']}})


def update_session_duration(session):
    session_start_time = g_db.sessions.find_one(get_session_id(session))['start_time']
    g_db.sessions.update(get_session_id(session), {"$set": {'duration': session['timestamp'] - session_start_time}})


def append_batches_count(n_packets_in_batch):
    g_db.kpi.update({"batches_count": {"$exists": True}},
                    {'$push':
                        {"batches_count": {
                            '$each': [n_packets_in_batch],
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def append_batches_rate(batch_rate):
    g_db.kpi.update({"batches_rates": {"$exists": True}},
                    {'$push':
                        {"batches_rates": {
                            '$each': [batch_rate],
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def append_batches_ratio(io_ratio):
    g_db.kpi.update({"batches_ratios": {"$exists": True}},
                    {'$push':
                        {"batches_ratios": {
                            '$each': [io_ratio],
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def append_durations(durations):
    g_db.kpi.update({"sessions_durations": {"$exists": True}},
                    {'$push':
                        {"sessions_durations": {
                            '$each': [durations],
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def append_bandwidths(bandwidths):
    g_db.kpi.update({"sessions_bandwidths": {"$exists": True}},
                    {'$push':
                        {"sessions_bandwidths": {
                            '$each': [bandwidths],
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def get_all_kpis():
    return list(g_db.kpi.find({}, {'_id': 0}))
