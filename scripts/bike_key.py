#!/usr/bin/env python3

import subprocess as sp
import kat_bike as kat
from enum import Enum
from random import randrange
import numpy as np

# check whether 'key' is already bytearray or try to initialize bytearray from hex string
bytelify = lambda key: key if type(key) == bytearray else bytearray(key) if type(key) == bytes else bytearray.fromhex(key)

# the target firmware uses little endian, so do we
byteorder = 'little'

class BIKE_key():
	"""class to handle BIKE keys

	Attributes
	----------
	level : kat_bike.Level
		this keys parameters are of this security level
	"""

	def __init__(self, key, lvl = "l00", mupq = False):
		"""
		Parameters
		----------
		key : bytearray | hex str
			if left as None the only attribute which will be set is
			self.level
		lvl : str
			can be a string to define a bike level, e.g. "l1", "l3",
			"l00", "l01"
		mupq : bool
			states if 'key' is in mupq format or only 'sk' + 'sigma' are
			given and other attributes need to be derived from that
		"""

		self.level = kat.get_lvl(lvl)

		if mupq:
			parsed = _parse_mupq_key(key, self.level)
		else:
			parsed = _parse_key(key, self.level)

		self._wlists = parsed[0]
		self._sk = parsed[1]
		self._pk = parsed[2]
		self._sigma = parsed[3]

	@property
	def sk(self) -> bytearray:
		"""sk : bytearray
			representation of the secret key"""
		return self._sk

	@property
	def h0(self) -> bytearray:
		"""the first half of the secret key"""
		return self.sk[:self.level.r_bytes]

	@property
	def h1(self) -> bytearray:
		"""the second half of the secret key"""
		return self.sk[self.level.r_bytes:]

	@property
	def pk(self) -> bytearray:
		"""the public key"""
		return self._pk

	@pk.setter
	def pk(self, key):
		"""setter for the public key

		key : either bytearray or hex string
		There is a check for the correct length of the key.
		"""
		key = bytelify(key)
		if len(key) == self.level.pk_bytes:
			self._pk = key
		else:
			raise Exception(f"Key length is {len(key)}, but expected {self.level.pk_bytes} for public key")

	@property
	def wlists(self):
		"""wlists : tuple(bytearray, bytearray)
		the weight lists, aka an index list of the secret keys set bits"""
		return self._wlists

	@property
	def sigma(self) -> bytearray:
		"""sigma : bytearray
		representation of the sigma"""
		return self._sigma


	@property
	def mupq_key(self) -> bytearray:
		"""retruns a bytearray containing the key in mupq format"""
		return self.wlists[0] + self.wlists[1] + self.sk + self.pk + self.sigma

	@property
	def wlists_as_int(self):
		"""get the weight lists as list of integers instead of bytearrays"""
		return _wlists_to_ilists(self._wlists)

	@property
	def coeff_list(self) -> ([int], [int]):
		"""get two lists of coefficients as representation of h0, h1"""
		coef0 = [0]*self.level.r_bits
		coef1 = [0]*self.level.r_bits

		bits = self.wlists_as_int

		for i in bits[0]:
			coef0[i] = 1

		for i in bits[1]:
			coef1[i] = 1

		return (coef0, coef1)


class FK_Kind(Enum):
	"""a small Enum to determine if we handle a type one or type two faulty key.
	ONE : h0 and h1 of the secret key have the same weight.
	TWOa | TWO : h1 has the correct weight, while h0's weight is altered.
	TWOb | THREE : h0 has the correct weight, while h1's weight is altered.
	UNDEF : catch all for key analysis. If key weight was higher and the weight list was faulted we cannot determine the kind.

	TWO and THREE are type two faulty keys according to Ketelsen, but for the implementation there might be a difference, that's why we observe them separately
	"""
	ONE = 1
	TWOa = 2 # add alias according to thesis
	TWOb = 3 # add alias according to thesis
	TWO = 2
	THREE = 3
	UNDEF = 4


class PK_Kind(Enum):
	"""Enum to determine wether the public key is derived from the weight lists or from the secret key.
	Only used for faulty key generation.
	"""
	WL = 0
	SK = 1


class WL_Kind(Enum):
	"""Enum to determine in which dependency the weight lists of a secret key are generated.
	Only used for faulty key generation.

	Note that the first three modes only take effect if the given weight
	is lower than the level's weight. They are only appending to the weight list(s).

	MULTI : missing indices will be a repetition of existing ones
	UNSET : missing indices will point to random bits (that were not set)
	INVALID : missing indices will point to values higher than level.r_bits
	MISMATCH : generate an independent weight list, which has nothing in common with the secret key
	UNDEF : catch all for key analysis. If key weight was higher and the weight list was faulted we cannot determine the kind.
	"""
	MULTI = 0
	UNSET = 1
	INVALID = 2
	MISMATCH = 3
	UNDEF = 4


class Fault(Enum):
	"""Enum to determine which part of the mupq key shall be faulted.
	Only used for faulty key generation.
	"""
	BOTH = 0
	SK = 1
	WL = 2


class FaultMode():
	"""a struct to hold the flags used for faulty key generation
	"""
	def __init__(self, key_kind:FK_Kind, pk_kind: PK_Kind, wl_kind: WL_Kind, fault: Fault):
		if not type(key_kind) == FK_Kind:
			raise TypeError("key_kind has to be a faulty key kind, FK_Kind")
		if not type(pk_kind) == PK_Kind:
			raise TypeError("pk_kind has to be a public key kind, PK_Kind")
		if not type(wl_kind) == WL_Kind:
			raise TypeError("wl_kind has to be a weight list kind, WL_Kind")
		if not type(fault) == Fault:
			raise TypeError("fault has to be a fault kind, Fault")
		self.SK = key_kind
		self.PK = pk_kind
		self.WK = wl_kind
		self.Fault = fault

	def __str__(self):
		return f"""Faulty key type {self.SK.name}
public key derived from {self.PK.name}
weight list kind {self.WK.name}
{self.Fault.name} {"were" if self.Fault == Fault.BOTH else "was"} faulted"""

	def __eq__(self, o):
		if type(o) == FaultMode:
			sk_undef = self.SK == FK_Kind.UNDEF or o.SK == FK_Kind.UNDEF
			wk_undef = self.WK == WL_Kind.UNDEF or o.WK == WL_Kind.UNDEF
			both = self.Fault == Fault.BOTH or o.Fault == Fault.BOTH

			kk = self.SK == o.SK or sk_undef
			pk = self.PK == o.PK or both
			wk = self.WK == o.WK or wk_undef
			fk = self.Fault == o.Fault or both
			return kk and pk and wk and fk
		else: return False

	def __hash__(self):
		return self.SK.value + 10 * self.PK.value + 100*self.WK.value +1000*self.Fault.value

	def new(self):
		"""returns a new object with the same values
		"""
		return FaultMode(self.SK, self.PK, self.WK, self.Fault)


def get_valid_faultmodes(fault=[], pk_kind=[], sk_kind=[], wl_kind=[]) -> [FaultMode]:
	"""Method to get a list of valid (and senseful) FaultModes

	Paramters
	---------
	sk_kind : List of FK_Kind which will be skipped.
	pk_kind : List of PK_Kind which will be skipped.
	wl_kind : List of WL_Kind which will be skipped.
	fault : List of Fault which will be skipped.

	returns a list of FaultMode
	"""
	fm = list()
	sk_kind.append(FK_Kind.UNDEF)
	wl_kind.append(WL_Kind.UNDEF)
	fault.append(Fault.SK)

	secret = {sk for sk in FK_Kind if sk not in sk_kind}
	public = {pk for pk in PK_Kind if pk not in pk_kind}
	weight = {wl for wl in WL_Kind if wl not in wl_kind}
	faults = {f for f in Fault if f not in fault}

	raw = [(sk,pk,wl,f) for sk in secret for pk in public for wl in weight for f in faults]

	for sk,pk,wl,f in raw:
		if pk == PK_Kind.WL:
			if wl not in [WL_Kind.MULTI, WL_Kind.UNSET]:
				continue
		fm.append(FaultMode(sk,pk,wl,f))
	return fm


def _parse_mupq_key(key, k_lvl=kat.get_lvl("l00")):
	"""parse a key and return its values as bytearrays in a tupple"""
	key = bytelify(key)
	if len(key) != k_lvl.mupq_sk_bytes:
		raise Exception(f"Key length does not fit, expected {k_lvl.mupq_sk_bytes} but got {len(key)}")
	c0 = k_lvl.weight_list_len // 2
	c1 = k_lvl.weight_list_len
	c2 = c1 + k_lvl.r_bytes*2
	c3 = c2 + k_lvl.pk_bytes

	wlists = (key[:c0], key[c0:c1])
	sk = key[c1:c2]
	pk = key[c2:c3]
	sigma = key[c3:]

	return (wlists, sk, pk, sigma)


def _parse_key(key, k_lvl=kat.get_lvl("l00")):
	"""parse a sk with sigma and calculate other key components which can be derived from that"""
	key = bytelify(key)

	h_bytes = k_lvl.r_bytes *2

	if len(key) != k_lvl.sk_bytes:
		raise Exception(f"Key length does not fit, expected {k_lvl.sk_bytes} but got {len(key)}")

	sk = key[:h_bytes]
	sigma = key[h_bytes:]

	wlists = _gen_wlists(sk, k_lvl)

	# the binary needs a key in mupq format, so we have to pad it to fit size
	pk = calculate_pk_from_sk(sk, k_lvl)

	return (wlists, sk, pk, sigma)


def _gen_wlist(h: bytearray, k_lvl: kat.Level) -> bytearray:
	"""generate the weight list for a vector h, as bytearray
	return value is in byte representation (little Endian)
	"""
	h_bin = bin(int.from_bytes(h, byteorder))[2:]
	h_idx = [i for i,h in enumerate(h_bin[::-1]) if h == "1"]
	h_byte = bytearray()
	for i in h_idx:
		h_byte += i.to_bytes(4, byteorder)

	# if the key had too little bits set
	for i in range(len(h_idx), k_lvl.d):
		# assume it makes sense to repeatedly point to the same bit
		h_byte += h_byte[0:4]

	# if there were too many bits set only return the first 'd'
	return h_byte[:k_lvl.d*4]


def _gen_wlists(sk : bytearray, k_lvl : kat.Level) -> (bytearray, bytearray):
	"""generate the weight index lists for a secret key composed of two vectors, sk = (h0,h1)

	return value is in byte representation (little Endian)
	"""
	if len(sk) != k_lvl.r_bytes *2:
		raise Exception(f"expected key length {k_lvl.r_bytes*2}, but got {len(sk)}")
	wl0 = _gen_wlist(sk[:k_lvl.r_bytes], k_lvl)
	wl1 = _gen_wlist(sk[k_lvl.r_bytes:], k_lvl)
	return (wl0, wl1)


def _wlist_to_ilist(wlist: bytearray) -> [int]:
	"""parse a bytearray of weight indices and return it as list of integers"""
	ilist = list()
	for i in range(len(wlist)//4):
		w = wlist[i*4:4+i*4]
		ilist.append(int.from_bytes(w, byteorder))
	return ilist


def _wlists_to_ilists(wlists: [bytearray, bytearray]) -> ([int], [int]):
	"""return the integer representation of a tuple of bytearray weight lists"""
	return (_wlist_to_ilist(wlists[0]), _wlist_to_ilist(wlists[1]))


def _ilist_to_bytearray(ilist: [int]) -> bytearray:
	"""counter part to _wlist_to_ilist()
	"""
	return bytearray().join([i.to_bytes(4, byteorder) for i in ilist])

def _ilists_to_bytearrays(ilists: ([int], [int])) -> ([bytearray, bytearray]):
	"""counter part to _wlists_to_ilists()
	"""
	return _ilist_to_bytearray(ilists[0]), _ilist_to_bytearray(ilists[1])


def gen_sk_from_wlist(wlists, r_bytes: int = kat.get_lvl('l00').r_bytes) -> bytearray:
	"""calculate the secret key corresponding to a wight list
	wlists : tuple(bytearray, bytearray) | tuple(int,int)

	returns a bytearray of length r_bytes *2
	"""
	wlists = wlists if not type(wlists[0]) == type(bytearray()) else _wlists_to_ilists(wlists)

	key0 = 0
	key1 = 0

	# have to separated loops, because for faulty key generation length might vary
	for w in wlists[0]:
		key0 |= 1 << w
	for w in wlists[1]:
		key1 |= 1 << w

	return key0.to_bytes(r_bytes, byteorder) + key1.to_bytes(r_bytes, byteorder)

def calculate_pk(sk, lvl="l00") -> bytearray:
	"""calculate the public key given a secret key
	sk : hex string | bytearray
		the secret key has to be in mupq (wlists, sk, pk, sigma) format
	"""
	l = kat.get_lvl(lvl)
	sk = bytelify(sk)

	ec, out = sp.getstatusoutput(f"../scripts/leve{kat.get_lvl_str(l)} {sk.hex()}")
	if ec:
		print("binary did not return SUCCESS")
		print(out)
		return -1
	return bytearray.fromhex(out)

def calculate_pk_from_sk(sk, lvl: kat.Level) -> bytearray:
	"""wrapper for calculate_pk(). Here sk is supposed to be only (h0,h1) as bytearray or hex string.
	"""
	sk = bytelify(sk)
	return calculate_pk(bytearray(lvl.weight_list_len) + sk + bytearray(lvl.r_bytes+ lvl.ss_bytes), lvl.name)

def _rand_wlist(d:int, lvl: kat.Level) -> [int]:
	"""generate a list of d unique integers
	"""
	ls = list()
	while len(ls) < d:
			rnd = randrange(lvl.r_bits)
			if rnd in ls:
				continue
			ls.append(rnd)
	return ls

def _faulty_wl(init_wl: [[int], [int]], wl_kind: WL_Kind, lvl: kat.Level) -> [[int], [int]]:
	"""Method to generate an integer weight list given an existing one.
	New one will be generated in respect to wl_kind and lvl. In respect to lvl means in
	particular, that the length of the returned weight lists have a length of lvl.d items.

	Note that for wl_kind == WL_Kind.MULTI | WL_Kind.UNSET | WL_Kind.INVALID nothing happens
	if the init_wl is already of size lvl.d or larger.
	"""
	wlists = [list(init_wl[0]), list(init_wl[1])]

	if wl_kind == WL_Kind.MULTI:
		# append an existing entry multiple times
		for i,l in enumerate(init_wl):
			while len(wlists[i]) < lvl.d:
				wlists[i].append(l[0])
	elif wl_kind == WL_Kind.UNSET:
		# append indices that were previously not set/available
		for i,l in enumerate(init_wl):
			while len(wlists[i]) < lvl.d:
				rnd = randrange(lvl.r_bits)
				if rnd not in wlists[i]:
					wlists[i].append(rnd)
	elif wl_kind == WL_Kind.INVALID:
		# append indices that were previously not set/available
		for i,l in enumerate(init_wl):
			while len(wlists[i]) < lvl.d:
				rnd = randrange(lvl.r_bits, 2*lvl.r_bits)
				if rnd not in wlists[i]:
					wlists[i].append(rnd)
	# previously weight list kinds only append to an existing list and don't take any
	# effect if the length of the initial weight list is larger than lvl.d
	elif wl_kind == WL_Kind.MISMATCH:
		# here we generate a new and independent weight list
		wlists = [_rand_wlist(lvl.d, lvl), _rand_wlist(lvl.d, lvl)]

	# possibly the initial weight list was longer than lvl.d, so we only return the
	# first lvl.d entries of each list
	return [wlists[0][:lvl.d], wlists[1][:lvl.d]]


def faulty_key(d, sk_kind : FK_Kind = FK_Kind.ONE, wl_kind : WL_Kind = WL_Kind.MULTI, pk_kind: PK_Kind = PK_Kind.SK, fault_kind: Fault = Fault.BOTH,  l="l00") -> BIKE_key:
	"""Method to generate faulty keys

	Parameters
	----------
	d : the aimed weight of h0/h1
	sk_kind : either type ONE or type TWO faulty key
	wl_kind : how the weight list is generated
	pk_kind : derive public key from secret key or from weight list
	fault_kind : fault either the secret key, the weight list or both
	l : level string
	"""
	lvl = kat.get_lvl(l)
	init_wlists = []
	lvl_wlists = []
	sk = bytearray()
	pk = bytearray()
	# sigma is simply a random bytearray, one could use a given sigma like bytearray(lvl.ss_bytes) as well.
	sigma = bytearray(randrange(255) for _ in range(lvl.ss_bytes))

	# generate initial index lists of faulted weight
	if sk_kind == FK_Kind.ONE:
		init_wlists.append(_rand_wlist(d, lvl))
		init_wlists.append(_rand_wlist(d, lvl))
	elif sk_kind == FK_Kind.TWO:
		init_wlists.append(_rand_wlist(d, lvl))
		init_wlists.append(_rand_wlist(lvl.d, lvl))
	elif sk_kind == FK_Kind.THREE:
		init_wlists.append(_rand_wlist(lvl.d, lvl))
		init_wlists.append(_rand_wlist(d, lvl))
	else:
		raise Exception(f"Unintended program flow. var sk_kind == {sk_kind}")

	# derive the faulted key from the faulted weight lists
	sk_faulty = gen_sk_from_wlist(init_wlists, lvl.r_bytes)
	wl_faulty = _faulty_wl(init_wlists, wl_kind, lvl)

	# set sk and lvl_wlists according to fault
	if fault_kind == Fault.BOTH:
		sk = sk_faulty
		lvl_wlists = wl_faulty
	elif fault_kind == Fault.SK:
		sk = sk_faulty
		# use WL_Kind.UNSET here because wl should not be faulted
		lvl_wlists = _faulty_wl(init_wlists, WL_Kind.UNSET, lvl)
	elif fault_kind == Fault.WL:
		# because we don't want the sk to be faulted we derive it from init_wlists.
		# We use WL_Kind.UNSET to generate a valid secret key
		sk = gen_sk_from_wlist(_faulty_wl(init_wlists, WL_Kind.UNSET, lvl), lvl.r_bytes)
		lvl_wlists = wl_faulty

	# calculate the public key according to the PK_Kind flag from either the secret key or the (faulted) weight list
	tmp_sk = 0
	if pk_kind == PK_Kind.SK:
		tmp_sk = sk
	elif pk_kind == PK_Kind.WL and wl_kind == WL_Kind.MISMATCH:
		tmp_sk = gen_sk_from_wlist(wl_faulty, lvl.r_bytes)
	elif pk_kind == PK_Kind.WL and not wl_kind == WL_Kind.INVALID:
		# we use init_wlists because they do not yet have invalid bit pointers
		tmp_sk = sk_faulty # equals gen_sk_from_wlist(init_wlists, lvl.r_bytes)
	else:
		raise Exception(f"Invalid combination of PK_Kind {pk_kind} and WL_Kind {wl_kind}")
	# finally calculate the public key
	pk = calculate_pk_from_sk(tmp_sk, lvl)

	# convert final weight lists into bytearray to return them
	wl_byte = _ilists_to_bytearrays(lvl_wlists)

	return BIKE_key(wl_byte[0] + wl_byte[1] + sk + pk + sigma, lvl=lvl.name, mupq=True)


def faulty_key_fm(d: int, fmode: FaultMode, l:str):
	"""simple wrapper for faulty_key(d)

	Note: if the weight d is higher than lvl.d the fmode.WK might be altered. If this
		is undesired behavior run this method with fmode.new().
	"""
	fk = faulty_key(d, fmode.SK, fmode.WK, fmode.PK, fmode.Fault, l)
	# change FaultMode.WK to UNDEF because other information gets lost if d>lvl.d
	if d > kat.get_lvl(l).d and (fmode.WK == WL_Kind.MULTI or fmode.WK == WL_Kind.UNSET or fmode.WK == WL_Kind.INVALID):
		fmode.WK = WL_Kind.UNDEF
	return fk


def analyze_key(mupq_key: bytearray, lvl: kat.Level) -> (FaultMode, (int, int), (int, int)):
	"""Method to determine the FaultMode of a mupq key

	Parameters
	----------
	mupq_key : a mupq key as bytearray
	lvl : kat.level. mupq_key and lvl have to match

	returns a FaultMode object and two tuples of ints. First tuple
		holds the weights of the weight list, second tuple holds
		the weights of the secret key.

	Note
	----
	PK_Kind might be wrong if, secret key and weight list, both were faulted.
	"""
	key_tuple = _parse_mupq_key(mupq_key, lvl)
	int_wlists = _wlists_to_ilists(key_tuple[0])
	sk = key_tuple[1]
	pk = key_tuple[2]

	# determine weights
	int_h0 = int.from_bytes(sk[:lvl.r_bytes], byteorder)
	int_h1 = int.from_bytes(sk[lvl.r_bytes:], byteorder)
	d_h0 = int_h0.bit_count()
	d_h1 = int_h1.bit_count()
	# secret key weights

	wl0 = set(int_wlists[0])
	wl1 = set(int_wlists[1])
	d_w0 = len(wl0)
	d_w1 = len(wl1)
	# weight list weights

	d0 = d_h0 if d_h0 != lvl.d else d_w0
	d1 = d_h1 if d_h1 != lvl.d else d_w1
	# weights which differ from lvl.d. If both fit they are lvl.d. This indicates
	# that the weights used to fault were higher than lvl.d and information got lost.

	# set flags if weights are correct
	d0_corr = d0 == lvl.d
	d1_corr = d1 == lvl.d


	# determine secret and public key kind
	key_kind = FK_Kind.ONE if d0 == d1 and not d0_corr else FK_Kind.TWO if not d0_corr and d1_corr else FK_Kind.THREE if d0_corr and not d1_corr else FK_Kind.UNDEF
	pk_kind = PK_Kind.SK if pk == calculate_pk_from_sk(sk, lvl) else PK_Kind.WL

	# pre calculations for the wl_kind determination
	# weight lists from given secret key
	wl_sk = _wlists_to_ilists(_gen_wlists(sk, lvl))
	# flags wether given weight lists and secret key weight lists are a subset or superset from each other.
	wl0_set = wl0.issubset(wl_sk[0]) if d_w0 < d_h0 else wl0.issuperset(wl_sk[0])
	wl1_set = wl1.issubset(wl_sk[1]) if d_w1 < d_h1 else wl1.issuperset(wl_sk[1])

	# determine weight list kind
	wl_kind = None
	if key_kind == FK_Kind.UNDEF:
		wl_kind = WL_Kind.UNDEF

	if wl_kind == None:
		if np.max([np.max(int_wlists[0]), np.max(int_wlists[1])]) > lvl.r_bits:
			wl_kind = WL_Kind.INVALID
		elif d_w0 == lvl.d and d_w1 == lvl.d and not (wl1_set or wl0_set):
			wl_kind = WL_Kind.MISMATCH
		elif d_w0 < lvl.d or d_w1 < lvl.d:
			wl_kind = WL_Kind.MULTI
		elif d_w0 > d_h0 or d_w1 > d_h1:
			wl_kind = WL_Kind.UNSET
		else:
			# catch all if other cases did not match
			wl_kind = WL_Kind.UNDEF


	# pre calculations for Fault kind
	# filter out invalid bit pointers
	wl_tmp = ([i for i in int_wlists[0] if i < lvl.r_bits],[i for i in int_wlists[1] if i < lvl.r_bits])

	# determine fault kind, i.e. which part of the mupq key was faulted (secret key, weight list or both)
	fault = None
	if wl_kind == WL_Kind.UNDEF and key_kind == FK_Kind.UNDEF:
		# seems like weights were higher than lvl.d when faulting and we lost
		# information so it has to be ->
		fault = Fault.WL
	elif wl_kind != WL_Kind.MISMATCH and sk == gen_sk_from_wlist(wl_tmp, lvl.r_bytes):
		# if we found out about wl_kind and the same secret key can be derived from the weight lists ->
		fault = Fault.BOTH
	elif d_h0 == lvl.d and d_h1 == lvl.d:
		# if the secret key weights match the level's weight obviously the weight list was faulted
		fault = Fault.WL
	elif d_h0 != lvl.d or d_h1 != lvl.d:
		# if the secret key's weights do not match with lvl.d the secret key was faulted
		fault = Fault.SK
	else:
		raise Exception("Unintended program flow.")

	fm = FaultMode(key_kind, pk_kind, wl_kind, fault)
	return fm, (d_w0, d_w1), (d_h0, d_h1)


def emph_difference(key: BIKE_key, lvl: kat.Level, loud=False) -> tuple:
	"""For further investigating vector and weight list differences

	returns lists of indices set in vectors but not in weight lists and vice versa
	"""
	key_tuple = _parse_mupq_key(key.mupq_key, lvl)
	int_wlists = _wlists_to_ilists(key_tuple[0])
	sk = key_tuple[1]
	# pk = key_tuple[2]
	int_h0 = int.from_bytes(sk[:lvl.r_bytes], byteorder)
	int_h1 = int.from_bytes(sk[lvl.r_bytes:], byteorder)
	int_h = (int_h0, int_h1)

	diff = (list(),list())
	for v,w in zip(int_h, int_wlists):
		v_set = set()
		ctr = 0
		for i,b in enumerate(bin(v)[::-1]):
			if b == '1': 
				ctr = ctr + 1
				v_set.add(i)
		v_diff = v_set.difference(w)
		w_diff = set(w).difference(v_set)
		diff[0].append(v_diff)
		diff[1].append(w_diff)
		if loud:
			print(f"{ctr} bits set in vector")
			print(f"{len(v_set.intersection(w))} bits are common with weight list")
			print(f"{v_diff} occur in vector but not in weight list")
			print(f"{w_diff} occur in weight list but not in vector")
	return diff

def __get_sk_ilist(key: BIKE_key):
	return _wlists_to_ilists(_gen_wlists(key.sk, key.level))

def find_cluster(i_list, max_dist=0, threshold=0):
	prv_c = list()
	i_list.sort()
	try:
		c = [i_list[0],0]
	except IndexError: return [[0,0]] 
	max = [0,0]
	for i in i_list:
		if c[0] < i - max_dist:
			if max[1] < c[1]:
				max[0] = c[0]
				max[1] = c[1]
			if c[1] > threshold:
				prv_c.append(c.copy())
			c[0] = i
			c[1] = 1
		else:
			c[1] += 1
	
	if max[1] < c[1]:
		max[0] = c[0]
		max[1] = c[1]
	return max,prv_c
