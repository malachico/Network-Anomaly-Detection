import numpy
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
    * number of https sessions per host, when the host is the destination IP
    * sessions duration
    * sessions bandwidth

    :type timestamp: time now
    :return:
    """
    ended_sessions = list(g_db["sessions"].find({"timestamp": {"$lt": timestamp - ENDED_SESSION_TIME}}))

    if not ended_sessions:
        append_bandwidths(0)
        append_durations(0)
        append_n_sessions(0)
        return

    all_sessions = list(g_db["sessions"].find())

    # Get the duration of sessions
    durations = map(lambda session: session['timestamp'] - session['start_time'], ended_sessions)

    # Get the bandwidth of sessions
    bandwidths = map(lambda session: session['n_bytes'], ended_sessions)

    # for each ended session get number of session
    ended_ips = set(map(lambda ended_session: ended_session['dest_ip'], ended_sessions))

    n_sessions = map(lambda ended_ip: len(filter(lambda session: ended_ip == session['dest_ip'], all_sessions)),
                     ended_ips)

    append_bandwidths(bandwidths)
    append_durations(durations)
    append_n_sessions(n_sessions)

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


def append_n_sessions(n_sessions):
    g_db.kpi.update({"n_sessions": {"$exists": True}},
                    {'$push':
                        {"n_sessions": {
                            '$each': [n_sessions],
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def get_all_kpis():
    return list(g_db.kpi.find({}, {'_id': 0}))


def drop_kpis():
    g_db.kpi.drop()