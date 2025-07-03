#!/bin/env sage
import sys

twos_complement = lambda num, bits: bin((num + (1 << bits)) % (1 << bits))[2:].zfill(bits)

def hex_sum(line):
	a = bytearray.fromhex(line)
	sum = 0
	for i in a:
		sum += i
	return hex(twos_complement(sum,8),2)

#if __name__ == "main":
	#line = input()
print(len(sys.argv))
print(hex_sum(sys.argv[1]))
