import common
import dal
import sniffer
import pandas as pd
import numpy as np
import seaborn as sns

def calc_presicion(tp, fp):
    if tp + fp == 0:
        return 0
    return tp / float(tp + fp)


def calc_recall(tp, fn):
    if tp + fn == 0:
        return 0
    return tp / float(tp + fn)


def calc_f1(p, r):
    if p + r == 0:
        return 0
    return (2 * p * r) / float(p + r)


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
    tp, tn, fp, fn = 0, 0, 0, 0
    tor_ips = ("88.198.23.221", "193.11.164.243", "85.17.30.79", "52.85.185.131")
    sessions = dal.get_epsilons()
    for session in sessions:
        if session['prob'] < epsilon:  # positive
            if session['dest_ip'] in tor_ips or session['src_ip'] in tor_ips:
                tp += 1
            else:
                fp += 1
        else:  # negative
            if session['dest_ip'] in tor_ips or session['src_ip'] in tor_ips:
                fn += 1
            else:
                tn += 1

    return tp, tn, fp, fn


if __name__ == '__main__':
    dal.init_db()
    data = pd.DataFrame.from_dict(dal.get_all_kpis())
    print data
    logged_data = map(lambda kpi: np.math.log(kpi, 2), data['batches_count'])
    # print logged_data

    sns.distplot(logged_data, bins=100)

    sns.plt.show()

