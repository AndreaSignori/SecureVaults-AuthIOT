from numpy.random import normal

import numpy as np

class TemperatureSensor:
    """
    This class wants to simulate the behaviour for a temperature sensor indoor. To do so we think about the temperature that has
    a normal distributio centered on 18°C.
    """
    def __init__(self, mean=18, std_deviation=1) -> None:
        self.mean = mean
        self.std_deviation = std_deviation

    def get_temperature(self) -> np.ScalarType:
        """
        Generate temperature measure from a normal distribution.

        :return: temperature measure
        """
        return normal(self.mean, self.std_deviation)