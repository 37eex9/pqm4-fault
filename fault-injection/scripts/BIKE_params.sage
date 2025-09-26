#!/usr/bin/env sage

import sys
import threshold
from sage.all import *

def hardcode_params(r, show=False) -> tuple:
	"""function to calculate the values that have to be hardcoded for a level
	in bike_defs.h and gf2x_inv.c. In decode.c the MAX_IT has to be defined, too.

	Parameters
	----------
	r : should be a prime number
	show : boolean to either print the values to console or not

	returns all the calculated values in a tuple.
	"""
	max_i = floor(log(r-2, 2)) + 1
	exp0_k = [2^i for i in range(max_i)]
	exp0_l = [inverse_mod((2^k) % r, r) for k in exp0_k]
	exp1_k = [(r-2)%(2^i) if ((r-2) & (1<<i)) else 0 for i in range(max_i)]
	exp1_l = [inverse_mod((2^k) % r, r) if k != 0 else 0 for k in exp1_k]
	blk = 2 ** ceil(log(r, 2))
	maxi = floor(log(r-2, 2)) + 1

	if show:
		print("gf2x_inv.c:")
		print(f"  EXP0_K_VALS {exp0_k}")
		print(f"  EXP0_L_VALS {exp0_l}")
		print(f"  EXP1_K_VALS {exp1_k}")
		print(f"  EXP1_L_VALS {exp1_l}")
		print(f"bike_defs.h:")
		print(f"  BLOCK_BITS {blk}")
		print(f"  MAX_I {maxi}")
	return(blk, exp0_k, exp0_l, exp1_k, exp1_l, maxi)


def _check_r(r: int, strict: bool)-> int:
	"""Method to check the mathematical properties of r.

	These are:
		Is 2 a primitive root of r?
		Is $(X^r -1)/(X -1) \in \mathbb{F}_2[X]$ irreducible?
	"""
	gen = None

	# get primitive root of
	S = GF(r, 'a')
	gen = S.multiplicative_generator()
	# is 2 primitive root?
	if not gen == 2 and strict:
		raise ValueError(f"2 should be a primitive root of GF({r}, but the primitive root returned is {gen}\nchoose a different r")

	# check wether $(X^r -1)/(X -1) \in \mathbb{F}_2[X]$ is irreducible
	a = var('a')
	R = GF(2**r, name='a')
	x = R.gen()
	try:
		irr = R(f'(a**{r} -1)/(a-1)')
		if irr.weight() == r:
			if show: print("irreducibility is fine")
		elif strict:
			if show:
				print(f"(X^{r} -1)/(X -1) is reducible in GF(2^{r}), so we skip here.")
	except ZeroDivisionError:
		print("something went wrong while checking the reducibility.")
	return gen


def properties(r:int, D:int =None, T:int =None, show=False, math=True, strict=True) -> dict:
	""" function to check some properties that should hold for a given r.

	Parameters
	----------
	r : should be a prime number
	D : optional, the half key weight. If not given an approximation is suggested.
	T : optional, the error weight, has to be smaller than sqrt(2*r). If not given an approximation is suggested.
	show : boolean to either print the values to console or not
	math : calculate exhaustive mathematical properties or skip them
	strict : abort calculation if first mathematical property does not hols (or continue)

	returns a tuple of the Hamming weight, the maximum error weight T, an error weight suggestion T, the multiplicative generator of GF(r),
		D, minimum threshold, threshold coefficients.
	"""

	# is r prime
	if is_prime(r):
		if show:
			print(f"r = {r} is prime")
	elif strict:
		if show:
			print("r is not prime, so we skip right here")
		return None

	gen = None
	if math:
		# exhaustive mathematical computations
		gen = _check_r(r, strict)

	# get Hamming weight and maximum error weight T
	hw = bin(r-2).count("1")
	maxT = floor(sqrt(2*r))

	# if unset, set suggestion for block weight D and error weight T (rough approximation)
	if D == None:
		D = maxT // 2 - 10
		D = D if D % 2 == 1 else D+1
	if T == None or T > maxT:
		T = ceil(maxT* 0.85)

	# set minimum threshold and threshold coefficients
	minThr = (D+1)/2
	coeff0, coeff1 = threshold.Calc_Threshold(r,D,T).compare()

	if show:
		print(f"Hamming weight of r-2 is {hw}")
		print(f"error weight has to be smaller than sqrt(2*r) >= {maxT}")
		print(f"  suggested error weight T = {T}")
		if gen == 2:
			print(f"2 is a generator of the finite field over r = {r}")
		elif math:
			print("2 is not a generator\nchoose a different value for r")
		print(f"suggested D = {D}")
		print(f"  THRESHOLD_COEFF0 = {coeff0}")
		print(f"  THRESHOLD_COEFF1 = {coeff1}")
		print(f"  THRESHOLD_MIN = {minThr} = (D+1)/2\n  has to be defined in bike_defs.h")

	return {'HW':hw, 'maxT':maxT, 'T':T, 'gen':gen, 'D':D, 'minThr':minThr, 'c0':coeff0, 'c1':coeff1}

def print_defines(r, D=None, T=None):
	""""method to print out a level definition, that simply has to be copied into the corresponding files.
	"""
	props = properties(r, D, T)
	params = hardcode_params(r)

	define = "#  define "

	print("bike_defs.h")
	print(f"{define} R_BITS {r}")
	print(f"{define} D      {props['D']}")
	print(f"{define} T      {props['T']}\n")
	print(f"{define} THRESHOLD_COEFF0 {props['c0']}")
	print(f"{define} THRESHOLD_COEFF1 {props['c1']}")
	print(f"{define} THRESHOLD_MIN    {props['minThr']}\n")
	print("// The gf2m code is optimized to a block in this case:")
	print(f"{define} BLOCK_BITS {params[0]}")

	print("\ngf2x_inv.c")
	print(f"// The parameters below are hard-coded for R={r}")
	print(f"bike_static_assert((R_BITS == {r}), gf2x_inv_r_doesnt_match_parameters);\n")
	print("// MAX_I = floor(log(r-2)) + 1")
	print(f"{define} MAX_I ({params[5]})")
	print(f"{define} EXP0_K_VALS \\\n    {params[1].__str__()[1:-1]}")
	print(f"{define} EXP0_L_VALS \\\n    {params[2].__str__()[1:-1]}")
	print(f"{define} EXP1_K_VALS \\\n    {params[3].__str__()[1:-1]}")
	print(f"{define} EXP1_L_VALS \\\n    {params[4].__str__()[1:-1]}")

if __name__ == "__main__":
	if len(sys.argv) != 2 and len(sys.argv) != 4:
		print(f"wrong amount of arguments, {len(sys.argv)}. Expects 1 or 3 argument: r or r, d, t")
		exit()
	try:
		r = int(sys.argv[1])
		D = int(sys.argv[2])
		T = int(sys.argv[3])
	except IndexError:
		D = None
		T = None

	z = r
	if properties(r, D, T, True):
		hardcode_params(z, True)
