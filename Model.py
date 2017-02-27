from scipy.stats import multivariate_normal

import dal



class Model:

    def __init__(self):
        self.cov_matrix = None
        self.mean_vec = None

    def calc_model(self):
        self.get_means_from_db()
        self.calc_cov_from_db()

    def get_means_from_db(self):
        pass

    def calc_cov_from_db(self):
        pass

    def calc_probability(self, sample):
        pass