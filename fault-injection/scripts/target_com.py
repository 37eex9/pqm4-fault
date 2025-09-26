#!/usr/bin/env python3
import serial
import sys
import platform
import kat_bike as kat


# method to handle different types of targets and get their serial output
t_raw = lambda target, len: target.read(len) if type(target) == serial.Serial else target.read(len, 0)


class Communication_Target():
    """a class to wrap communication with a target board

    this is provided to make the communication less error prone


    There are 5 base commands
    keygeneration
    encapsulation
    decapsulation
    read
        a encapsulated shared secret
        b decapsulated shared secret
        p public key
        s secret key
        c ciphertext
    write
        p public key
        s secret key
        c ciphertext
    """
    target = None

    def __init__(self, target, lvl:str):
        self.target = target
        self.lvl = kat.get_lvl(lvl)


    def check_done(self):
        """firmware methods which do not send data at least send a marker
        to signal, that the operation is completed. This method waits for the
        marker to keep host and target board synchronous.
        """
        # check for '\x01\x00#' in response to verify correct computation
        x = t_raw(self.target, 3)
        if type(self.target) == serial.Serial:
            return b'\x01\x00#' == x
        else:
            # chipwhisperer target does not give byte output from serial, but # has to match
            return x[2] == '#'


    def check_done_to(self):
        """check_done() with timeout.
        Use with care. If invoked too early, target may not finish computation in time
        and timeout may be interpreted as target crash.

        firmware methods which do not send data at least send a marker
        to signal, that the operation is completed. This method waits for the
        marker to keep host and target board synchronous.
        In opposite to check_done() this method set a timeout for reading.

        Meant for fault injection, currently only supported by the chipwhisperer target.
        This code supports serial.Serial target, too.
        """
        _ser = type(self.target) == serial.Serial
        if _ser: self.target.timeout = 250
        x = self.target.read(3)
        if _ser: self.target.timeout = None

        if len(x) == 3:
            return x[2] == '#'
        else:
            return False

    # kem functions
    def keygen(self):
        """trigger keygeneration on target"""
        self.target.write(b'k')
        return self.check_done()

    def keygen_async(self):
        """trigger keygeneration on target without waiting for target answer
        if this method is used one should call check_done()"""
        self.target.write(b'k')

    def encaps(self):
        """trigger encapsulation on target"""
        self.target.write(b'e')
        return self.check_done()

    def encaps_async(self):
        """trigger encapsulation on target without waiting for target answer
        if this method is used one should call check_done()"""
        self.target.write(b'e')

    def decaps(self):
        """trigger decapsulation on target"""
        self.target.write(b'd')
        return self.check_done()

    def decaps_async(self):
        """trigger decapsulation on target without waiting for target answer
        if this method is used one should call check_done()"""
        self.target.write(b'd')

    # read functions
    def r_ss_dec(self):
        """read shared secret which is a result after last decapsulation"""
        self.target.write(b"ra")
        ret = kat.t_read(self.target, self.lvl.ss_bytes)
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return ret

    def r_ss(self):
        """read shared secret which is a result after last encapsulation"""
        self.target.write(b"rb")
        ret = kat.t_read(self.target, self.lvl.ss_bytes)
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return ret

    def r_pk(self):
        """read public key which is a result of last keygeneration
        or was set via write method"""
        self.target.write(b"rp")
        ret = kat.t_read(self.target, self.lvl.pk_bytes)
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return ret

    def r_sk_mupq(self):
        """read secret key which is a result of last keygeneration
        or was set via write method

        returns the whole mupq key
        """
        self.target.write(b"rs")
        ret = kat.t_read(self.target, self.lvl.mupq_sk_bytes)
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return ret

    def r_sk(self):
        """read secret key which is a result of last keygeneration
        or was set via write method

        returns only KAT secret key, ((h0,h1), syndrome)
        """
        self.target.write(b"rs")
        ret = kat.parse_mupq_sk(self.lvl.name, kat.t_read(self.target, self.lvl.mupq_sk_bytes))
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return ret

    def r_ct(self):
        """read ciphertext which is a result of last keygeneration
        or was set via write method"""
        self.target.write(b"rc")
        ret = kat.t_read(self.target, self.lvl.ct_bytes)
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return ret

    # write functions
    def w_sk(self, key):
        """write secret key to target board

        requires all the mupq key information
        does not set the public key on the target
        """

        if self.lvl.mupq_sk_bytes != len(key):
            print(f"key size does not fit for level {self.lvl}: required {self.lvl.pk_bytes}, got {len(key)}")
            return False
        self.target.write(b"ws")
        self.target.write(key)
        return self.check_done()

    def w_pk(self, key):
        """write public key to the target board"""

        if self.lvl.pk_bytes != len(key):
            print(f"key size does not fit for level {self.lvl}: required {self.lvl.pk_bytes}, got {len(key)}")
            return False
        self.target.write(b"wp")
        self.target.write(key)
        return self.check_done()

    def w_ct(self, ct):
        """write ciphertext to the target board"""

        if self.lvl.ct_bytes != len(ct):
            print(f"cipher text size does not fit for level {self.lvl}: required {self.lvl.ct_bytes}, got {len(ct)}")
            return False
        self.target.write(b"wc")
        self.target.write(ct)
        return self.check_done()


    def c_ss(self):
        """Method to check if encapsulation and decapsulation did work.
        Most computation is done on the target board to minimize serial communication.

        return checksum of ss_a - ss_b (bytewise). Successful if return is b'/x00'
        """
        self.target.write(b"c")
        check = kat.t_read(self.target, 1)
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return check

    # trigger settings on target
    def __trig_h(self, h, cnt):
        """set trigger"""
        cmd = b't' + h.to_bytes(1, 'little') + cnt.to_bytes(2, 'little')
        self.target.write(cmd)
        return self.check_done()

    def trig_h0(self, cnt):
        """set trigger counter for h1"""
        return self.__trig_h(0, cnt)

    def trig_h1(self, cnt):
        """set trigger counter for h1"""
        return self.__trig_h(1, cnt)


    # misc functions
    # led toggle
    def l_togg(self, led=0):
        """supposed to toggle led"""
        self.target.write(bytearray(f"l{led}", 'ASCII'))
        return (self.check_done())

    def reset_prng(self):
        """resets pseudo random number generator on CWLITEARM"""
        self.target.write(b"n")
        return self.check_done()

    def regen_prng(self):
        """triggers regeneration of pseudo random number generator on CWLITEARM

        can be used to put prng in a specific state which differs from the
        initial state, which is achieved after reset_prng()."""
        self.target.write(b"o")
        return self.check_done()

    # get some bytes from (pseudo) random number generator
    def get_rand(self, len=1):
        """read the next 'len' bytes from prng

        can be used to verify the state of the prng
        """

        if len > 20 and len < 1:
            print(f"length should be between 1 and 20, but is {len}")
            return

        cmd = b'p' + len.to_bytes(2, 'little')
        self.target.write(cmd)
        ret = kat.t_read(self.target, len)
        if not self.check_done():
            raise Exception("Communication out of sync.")
        return ret
