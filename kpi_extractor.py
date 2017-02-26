from sessions_extractor import handle_sessions
from batches_extractor import handle_batches


def parse_packet(timestamp, packet, state_context):
    """
    extract KPIs we use for our engine from the packet

    :param timestamp: timestamp of the packet arrival
    :param packet:
    :return:
    """
    handle_sessions(timestamp, packet)
    state_context.handle_batch(timestamp, packet)
