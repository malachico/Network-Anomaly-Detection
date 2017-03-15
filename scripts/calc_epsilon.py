import common
import dal
import sniffer


def calc_presicion(tp, fp):
    return tp / tp + fp


def calc_recall(tp, fn):
    return tp / tp + fn


def calc_f1(p, r):
    return (2 * p * r) / (p + r)


def run_cv_set():
    print "STARTING FILE : CV0"
    sniffer.read_pcap("/home/malachi/PycharmProjects/ADE/pcaps/cross-validation/cv0.pcap")

    print "STARTING FILE : CV1"
    sniffer.read_pcap("/home/malachi/PycharmProjects/ADE/pcaps/cross-validation/cv1.pcap")

    print "STARTING FILE : CV2"
    sniffer.read_pcap("/home/malachi/PycharmProjects/ADE/pcaps/cross-validation/cv2.pcap")

    print "STARTING FILE : CV3"
    sniffer.read_pcap("/home/malachi/PycharmProjects/ADE/pcaps/cross-validation/cv3.pcap")


def calc_epsilon_results(epsilon):
    sessions = dal.get_epsilons()
    pass


if __name__ == '__main__':
    """
    before running this script run the training set"""
    dal.init_db()

    # dal.drop_sessions()

    run_cv_set()

    sessions_probs = dal.get_epsilons()

    sorted_values = sorted(sessions_probs.values())

    min_values = sorted_values[:len(sorted_values) / 10]

    f1_results = {}

    # calc model from training set
    common.build_model()

    for epsilon in min_values:
        # Calc tp, tn, fp, fn for epsilon
        tp, tn, fp, fn = calc_epsilon_results(epsilon)

        # Calc precision and recall for epsilon
        p = calc_presicion(tp, fp)
        r = calc_recall(tp, fn)

        # Calc F1 score
        f1_results[epsilon] = calc_f1(p, r)

    print "epsilon =", max(f1_results.items(), key=lambda x: x[1])[1]
