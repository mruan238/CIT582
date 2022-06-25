import math

def num_BTC(b):
    ntokens = 50
    reward = 50
    blocks = 1
    while (blocks < b):
        if (blocks % 210_000==0):
            reward = reward / 2
        ntokens = ntokens + reward
        blocks = blocks + 1

    return float(ntokens)

