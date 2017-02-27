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


def remove_old_sessions(timestamp):
    """
    remove sessions which are older than g_session_time

    :type timestamp: time now
    :return:
    """
    ended_sessions = list(g_db["sessions"].find({"timestamp": {"$lt": timestamp - ENDED_SESSION_TIME}}))

    durations = map(lambda session: session['timestamp'] - session['start_time'], ended_sessions)
    bandwidths = map(lambda session: session['n_bytes'], ended_sessions)

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
                            '$each': durations,
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)


def append_bandwidths(bandwidths):
    g_db.kpi.update({"sessions_bandwidths": {"$exists": True}},
                    {'$push':
                        {"sessions_bandwidths": {
                            '$each': bandwidths,
                            '$slice': -common.NUMBER_OF_BATCHES_TO_REMEMBER}}}, upsert=True)
