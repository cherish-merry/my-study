def addr2dec(addr):
    items = [int(x) for x in addr.split(".")]
    return sum([items[j] << [24, 16, 8, 0][j] for j in range(4)])


def dec2addr(dec):
    return ".".join([str(dec >> x & 0xff) for x in [0, 8, 16, 24]])


print(dec2addr())