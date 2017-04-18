import pandas as pd
from numpy import *
from scipy.stats import multivariate_normal

import dal


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


def norm_pdf_multivariate(x, mu, sigma):
    size = len(x)
    if size != len(mu) or (size, size) != sigma.shape:
        raise NameError("The dimensions of the input don't match")

    det = linalg.det(sigma)

    if det == 0:
        raise NameError("The covariance matrix can't be singular")

    norm_const = 1.0 / (math.pow((2 * math.pi), float(size) / 2) * math.pow(det, 1.0 / 2))
    x_mu = matrix(x - mu)
    inv = sigma.I
    result = math.pow(math.e, -0.5 * (x_mu * inv * x_mu.T))
    return norm_const * result


if __name__ == '__main__':
    dal.init_db()
    data = pd.DataFrame.from_dict(dal.get_kpis('batches_kpis'))
    X = data[['io_ratios', 'packets_count']]
    y = data['anomaly']
    # batches_model = multivariate_normal(mean=X.mean(), cov=X.cov())
    # batches_model.pdf(X)
    print norm_pdf_multivariate([1, 1], array(X.mean()), matrix(X.cov()))
