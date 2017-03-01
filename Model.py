import dal
import numpy


class Model:

    def __init__(self):
        self.cov_matrix = self.calc_cov_matrix()
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

    def calc_cov_matrix(self):
        kpis = dal.get_all_kpis()

        numpy.cov