#!/usr/bin/env python3

import struct

si = 1 # short int (2 bytes)
i  = 2 # int (4 bytes)
li = 3 # long long int (8 bytes)

packed_bytes_le = struct.pack('<hiq', si, i, li)
print("little endian: ", packed_bytes_le)

packed_bytes_be = struct.pack('>hiq', si, i, li)
print("big endian:    ", packed_bytes_be)

packed_bytes_native = struct.pack('@hiq', si, i, li)
print("native:        ", packed_bytes_native)


