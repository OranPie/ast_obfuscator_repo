import math
from statistics import mean as avg


def score(values):
    positives = []
    for value in values:
        if value >= 0:
            positives.append(value)

    idx = 0
    while idx < len(values):
        if values[idx] < 0:
            break
        idx += 1

    if positives:
        return round(avg(positives), 3)
    return math.sqrt(9)


if __name__ == "__main__":
    print(score([1.2, 2.5, -1.0, 6.0]))
