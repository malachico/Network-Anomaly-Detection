import time
import urllib2

import dal

TIME_TO_REFRESH = 30 * 60  # half an hour
nodes_url = "https://www.dan.me.uk/torlist/"
# nodes_url = 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt'  # for debugging


# -------------------------------- functions
def refresh_blacklist_db():
    """

    Refresh the node list in DB and updates the list
    """
    # Download
    data = urllib2.urlopen(nodes_url)

    # Convert to IPs list
    nodes = frozenset(data.read().split("\n"))

    # update last time updated
    g_last_time_refreshed = time.time()

    # update DB
    dal.write_nodes(nodes, g_last_time_refreshed)


def check_nodes(session, tor_ips):
    """

    :param tor_ips: Known ToR IPs found in DB
    :param session: Session to check
    :return: True if one of the IPs is in the nodes list and print and alert
    """
    if session['src_ip'] in tor_ips:
        dal.alert(session, 1)
        return True

    if session['dest_ip'] in tor_ips:
        dal.alert(session, 1)
        return True

    return False


def time_to_refresh():
    """

    :return: True if it has been long since last update
    """
    return time.time() - dal.get_blacklist_ts() > TIME_TO_REFRESH
