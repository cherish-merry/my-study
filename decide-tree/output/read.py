import struct
with open('feature', 'rb') as f:
    data = f.read()
unpack_result = struct.unpack('hhl', data[0:16])
print(unpack_result)
