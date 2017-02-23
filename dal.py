from pymongo import MongoClient

g_db = None
SESSION_TIME = 7 * 60


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
    return g_db['sessions'].find(get_session_id(session)) is not None


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
    g_db["sessions"].remove({"timestamp": {"$lt": timestamp - SESSION_TIME}}, multi=True)


def update_session_bytes(session, n_bytes):
    g_db["sessions"].update(get_session_id(session), {"$inc": {'n_bytes': n_bytes}})


def update_session_timestamp(session):
    g_db["sessions"].update(get_session_id(session), {"$set": {'timestamp': session['timestamp']}})
