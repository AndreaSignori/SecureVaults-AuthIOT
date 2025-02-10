from matplotlib import pyplot as plt

from sensors import TemperatureSensor

if __name__ == '__main__':
    sensor = TemperatureSensor()
    samples = list()

    for i in range(10000000):
        samples.append(sensor.get_temperature())

    plt.hist(samples, bins=range(13, 23))
    plt.show()
