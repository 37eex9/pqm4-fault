#!/usr/bin/env python3
import math
import sys
import serial
from io import TextIOWrapper
import chipwhisperer.capture.targets as cwt
"""This script is supposed to help handling KATs

There are multiple security levels defined
To add a new security level define a constant level
(e.g. l1 = Level(12323, 71)) and update the methods
get_lvl() and get_lvl_str() accordingly.
"""

# method to handle different types of targets and get their serial output
t_raw = lambda target, len: target.read(len) if type(target) == serial.Serial else target.read(len, 0) if type(target) == cwt.SimpleSerial else target.read(len) if type(target) == TextIOWrapper else None

def sync_cnt(target):
	"""Synchronization method: waits until '=' appears in serial stream.
	"""
	while not t_raw(target, 1) == '=': continue

def sync_entry_start(target):
	"""Synchronization method: waits until '$' appears in serial stream.
	'$' is used in kat.c as marker for the start of a transmission.
	"""
	while not t_raw(target, 1) == '$': continue

def sync_entry_end(target):
	"""Checks if the marker for the end of a transmission is received.
	"""
	# check for '\x01\x00#' in response to verify correct computation
	x = t_raw(target, 3)
	if type(target) == serial.Serial:
		return b'\x01\x00#' == x
	else:
		# chipwhisperer target does not give byte output from serial, but # has to match
		return x[2] == '#'


class Level():
	"""class to represent a BIKE security level

	holds almost all the relevant values to define a security level
	for BIKE. Only the threshold coefficients are not present.
	"""
	r_bits = 0
	r_bytes = 0
	d = 0
	pk_bytes = 0
	sk_bytes = 0
	ct_bytes = 0
	ss_bytes = 32
	M_Bytes = 32
	weight_list_len = 0
	mupq_sk_bytes = 0

	def __init__(self, block_len, block_weight):
		"""
		Parameters
		----------
		block_len : int
			the block length (in specification it is called 'r') in bits
		block_wight : int
			the weight of h0 or h1, in other words the half weight of the secret key
		"""
		self.r_bits = block_len
		self.d = block_weight
		self.r_bytes = math.ceil(self.r_bits / 8)
		self.pk_bytes = self.r_bytes
		self.sk_bytes = 2 * self.r_bytes + self.M_Bytes
		self.ct_bytes = self.r_bytes + self.M_Bytes
		self.weight_list_len = self.d * 4 * 2 # in pqm4 there is a weight index for the private key
		# one of 2*d = w set bits is indexed by a 32bit integer
		self.mupq_sk_bytes = self.weight_list_len + self.pk_bytes + self.sk_bytes


	def __str__(self):
		return get_lvl_str(self)

	@property
	def name(self):
		return get_lvl_str(self)

	def print(self):
		print(self.r_bits)
		print(self.r_bytes)
		print(self.d)
		print(self.pk_bytes)
		print(self.sk_bytes)
		print(self.M_Bytes)
		print(self.weight_list_len)

# self defined security levels
# [Ketelsen]
l00 = Level(2053,23)
l01	= Level(7109,41)
# gf2x_params.sage
l11 = Level(773, 9)
l12 = Level(1019, 13)
l13 = Level(1283, 15)
l14 = Level(2029, 21)
l15 = Level(2053, 23)
l16 = Level(2069, 23)
l17 = Level(4021, 35)
l18 = Level(4099, 35)
l20 = Level(4813, 39)
l21 = Level(5501, 43)
l22 = Level(6323, 47)
# levels defined in pqm4
l1	= Level(12323,71)
l3	= Level(24659,103)

# KAT seed length
seed_len = 48

class KAT_entry():
	"""class to hold all the information given in a KAT"""
	count = 0
	seed = 0
	pk = 0
	sk = 0
	ct = 0
	ss = 0

	def __str__(self):
		return f"count = {self.count}\n\
seed = {self.seed.hex()}\n\
pk = {self.pk.hex()}\n\
sk = {self.sk.hex()}\n\
ct = {self.ct.hex()}\n\
ss = {self.ss.hex()}"

	def __eq__(self, o):
		if not type(o) == KAT_entry:
			return False
		return self.seed == o.seed and self.pk == o.pk and self.sk == o.sk and self.ct == o.ct and self.ss == o.ss


def get_lvl(l: str) -> Level:
	"""get a kat_bike.Level() object from a string"""
	if l == "l00" or l == "l0":
		return l00
	elif l == "l01" or l == "l10":
		return l01
	elif l == "l1":
		return l1
	elif l == "l3":
		return l3
	elif l == "l11":
		return l11
	elif l == "l12":
		return l12
	elif l == "l13":
		return l13
	elif l == "l14":
		return l14
	elif l == "l15":
		return l15
	elif l == "l16":
		return l16
	elif l == "l17":
		return l17
	elif l == "l18":
		return l18
	elif l == "l20":
		return l20
	elif l == "l21":
		return l21
	elif l == "l22":
		return l22
	else:
		print("define level, e.g. 'l00'")
		raise Exception("No valid level")


def get_lvl_str(l: Level) -> str:
	"""get a level string from a Level() object"""
	r = l.r_bits
	if r == 7109:
		return "l01"
	elif r == 12323:
		return "l1"
	elif r == 24659:
		return "l3"
	elif r == 773:
		return "l11"
	elif r == 1019:
		return "l12"
	elif r == 1283:
		return "l13"
	elif r == 2029:
		return "l14"
	elif r == 2053:
		return "l15"
	elif r == 2069:
		return "l16"
	elif r == 4021:
		return "l17"
	elif r == 4099:
		return "l18"
	elif r == 4813:
		return "l20"
	elif r == 5501:
		return "l21"
	elif r == 6323:
		return "l22"
	elif r == 2053:		# TODO decide either to keep l15 or l00
		return "l00"
	raise Exception("level not implemented")


def read_rsp(l="l00", filepath="../KAT/") -> dict:
	"""read a KAT response file to know all the values that are to be expected

	Parameters
	----------
	l : str
		level string
	filepath : str
		the file path where to find the KAT files. The file name is derived from the level

	returns a list of KAT_entry() objects
	"""

	level = get_lvl(l)

	if filepath[-1] != '/': filepath += '/'

	rsp = None
	try:
		filename = f"{filepath}PQCkemKAT_BIKE_{level.sk_bytes}.rsp"
		rsp = open(filename, "r")
	except:
		print("Something went wrong while opening file: " + filename)
		return None

	# put stream pointer to second line
	rsp.readline()

	kat = dict()
	count = 0
	while count < 99:
		entry = KAT_entry()
		# first line is empty
		rsp.readline()

		line = rsp.readline()
		entry.count = int(line.split(" ")[2])
		line = rsp.readline()
		entry.seed 	= bytearray.fromhex(line.split(" ")[2])
		line = rsp.readline()
		entry.pk 	= bytearray.fromhex(line.split(" ")[2])
		line = rsp.readline()
		entry.sk 	= bytearray.fromhex(line.split(" ")[2])
		line = rsp.readline()
		entry.ct 	= bytearray.fromhex(line.split(" ")[2])
		line = rsp.readline()
		entry.ss 	= bytearray.fromhex(line.split(" ")[2])

		kat[entry.count] = entry
		count = entry.count

	rsp.close()
	return kat


def parse_mupq_sk(l: str, mupq_key: bytearray) -> bytearray:
	"""parse a mupq bike secret key and return only KAT secret key

	mupq sk holds (weight lists, (h0,h1), pk, syndrome)
	KAT sk holds only ((h0,h1), syndrome)
	"""
	lvl = get_lvl(l)
	key = mupq_key
	key = key[lvl.weight_list_len:] # cut off weight index list
	key = key[:lvl.r_bytes*2] + key[-lvl.M_Bytes:]
	return key


# read function, handles two different boars with different specific read methods
t_read = lambda target, len: bytearray.fromhex(target.read(len*2).decode()) if type(target) == serial.Serial else bytearray.fromhex(target.read(len*2, 0)) if type(target) == cwt.SimpleSerial else bytearray.fromhex(target.read(2*len)) if type(target) == TextIOWrapper else None


def read_target(target, lvl = "l00", n=100) -> dict:
	"""reads the output stream of a target which computes KATs

	this method is supposed to be called directly after a target reset, as the target firmware starts to output all the data right after boot

	Parameters
	----------
	target : either a serial interface, a file or a chipwhisperer target

	lvl : str
		a level string

	n : int
		listens to the first 'n' responses from the target

	Returns
	-------
	list
		a list of 'n' KAT_entries
	"""

	target_kat = dict()
	fails = list()
	k_lvl = get_lvl(lvl)
	cnt = 0

	for i in range(n): # one can lower the range to only wait for the first n entries generated from the target
		if cnt == n: break
		cnt += 1
		try:
			sync_cnt(target) # read start symbol to synchronize
			entry = KAT_entry()

			# sync_entry_start(target)
			entry.count = 	int.from_bytes(t_read(target, 1), 'little')
			if not sync_entry_end(target): raise RuntimeError("Counter out of sync")
			print(f"received {entry.count} as counter")
			
			# sync_entry_start(target)
			entry.seed 	= 	t_read(target, seed_len)
			if not sync_entry_end(target): raise RuntimeError("Seed out of sync")

			# sync_entry_start(target)
			entry.pk 	= 	t_read(target, k_lvl.pk_bytes)
			if not sync_entry_end(target): raise RuntimeError("Public Key out of sync")

			# sync_entry_start(target)
			entry.sk 	= 	parse_mupq_sk(lvl, t_read(target, k_lvl.mupq_sk_bytes))
			if not sync_entry_end(target): raise RuntimeError("Secret Key out of sync")

			# sync_entry_start(target)
			entry.ct 	= 	t_read(target, k_lvl.ct_bytes)
			if not sync_entry_end(target): raise RuntimeError("Ciphertext out of sync")

			# sync_entry_start(target)
			entry.ss 	= 	t_read(target, k_lvl.ss_bytes)
			if not sync_entry_end(target): raise RuntimeError("Shared secret (orig) out of sync")

			# sync_entry_start(target)
			ss 			=	t_read(target, k_lvl.ss_bytes)
			if not sync_entry_end(target): raise RuntimeError("Shared secret (decaps) out of sync")

			if ss != entry.ss:
				fails.append(i)
			target_kat[entry.count] = entry
		except RuntimeError as error: print(error)
		except ValueError as error: print(error)

	if len(fails) > 0:
		print("decoding failure happend in")
		print(fails)

	return target_kat


if __name__ == "__main__":
	"""simple test to verify reading and parsing a KAT file works

	expects a level string as argument
	optional a filepath where to find KAT files
	"""
	kat = None
	try:
		if len(sys.argv) == 2:
			kat = read_rsp(sys.argv[1])
		elif len(sys.argv) == 3:
			kat = read_rsp(sys.argv[1], sys.argv[2])

		for i in kat:
			i.print()
	except:
		print(f"\nUsage: {sys.argv[0]} l[00-17|1|3] [path/to/kat/files]")