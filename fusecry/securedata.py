"""
Store any data in memory as pair of xored byte values.
"""

import os
import pickle
import hashlib

class Hidden(object):

    def __init__(self, value):
        self.__salt = os.urandom(8)
        self.__obfuscate(value)

    def __obfuscate(self, value):
        """
        Store value as 2 xor-able values.
        """
        bvalue = pickle.dumps(value)
        self.__two = int.from_bytes(
            os.urandom(len(bvalue)),
            byteorder='big',
            signed=False
            )
        self.__one = int.from_bytes(
            bvalue,
            byteorder='big',
            signed=False
            ) ^ self.__two
        self.__hash = int(hashlib.sha1(bvalue+self.__salt).hexdigest(),16)

    def __reveal(self):
        """
        Xor 2 stored values and return functional object.
        """
        bvalue = bytes.fromhex( hex(self.__one ^ self.__two)[2:] )
        check_hash = int(hashlib.sha1(bvalue+self.__salt).hexdigest(),16)
        if self.__hash != check_hash:
            raise ValueError('secure_data object has been tampered with.')
        return pickle.loads(bvalue)

    # conversions
    def type(self): return type(self.__reveal())
    def __str__(self): return str(self.__reveal())
    def __int__(self): return int(self.__reveal())
    def __bool__(self): return bool(self.__reveal())

    # logic byte operations
    def __and__(self, other): return self.__reveal() & other
    def __rand__(self, other): return other & self.__reveal()
    def __iand__(self, other):
         self.__obfuscate(self.__reveal() & other)
         return self
    def __or__(self, other): return self.__reveal() | other
    def __ror__(self, other): return other | self.__reveal()
    def __ior__(self, other):
         self.__obfuscate(self.__reveal() | other)
         return self
    def __xor__(self, other): return self.__reveal() ^ other
    def __rxor__(self, other): return other ^ self.__reveal()
    def __ixor__(self, other):
         self.__obfuscate(self.__reveal() ^ other)
         return self
    def __lshift__(self, other): return self.__reveal() << other
    def __rlshift__(self, other): return other << self.__reveal()
    def __ilshift__(self, other):
         self.__obfuscate(self.__reveal() << other)
         return self
    def __rshift__(self, other): return self.__reveal() >> other
    def __rrshift__(self, other): return other >> self.__reveal()
    def __irshift__(self, other):
         self.__obfuscate(self.__reveal() >> other)
         return self

    # math comparison
    def __lt__(self, other): return self.__reveal() < other
    def __le__(self, other): return self.__reveal() <= other
    def __eq__(self, other): return self.__reveal() == other
    def __ne__(self, other): return self.__reveal() != other
    def __gt__(self, other): return self.__reveal() > other
    def __ge__(self, other): return self.__reveal() >= other

    # math operations
    def __add__(self, other): return self.__reveal() + other
    def __radd__(self, other): return other + self.__reveal()
    def __iadd__(self, other):
        self.__obfuscate(self.__reveal() + other)
        return self
    def __sub__(self, other): return self.__reveal() - other
    def __rsub__(self, other): return other - self.__reveal()
    def __isub__(self, other):
        self.__obfuscate(self.__reveal() - other)
        return self
    def __mul__(self, other): return self.__reveal() * other
    def __rmul__(self, other): return other * self.__reveal()
    def __imul__(self, other):
        self.__obfuscate(self.__reveal() * other)
        return self
    def __matmul__(self, other): return self.__reveal() @ other
    def __rmatmul__(self, other): return other @ self.__reveal()
    def __imatmul__(self, other):
        self.__obfuscate(self.__reveal() @ other)
        return self
    def __pow__(self, other): return self.__reveal() ** other
    def __rpow__(self, other): return other ** self.__reveal()
    def __ipow__(self, other):
        self.__obfuscate(self.__reveal() ** other)
        return self
    def __truediv__(self, other): return self.__reveal() / other
    def __rtruediv__(self, other): return other / self.__reveal()
    def __itruediv__(self, other):
        self.__obfuscate(self.__reveal() / other)
        return self
    def __floordiv__(self, other): return self.__reveal() // other
    def __rfloordiv__(self, other): return other // self.__reveal()
    def __ifloordiv__(self, other):
        self.__obfuscate(self.__reveal() // other)
        return self
    def __mod__(self, other): return self.__reveal() % other
    def __rmod__(self, other): return other % self.__reveal()
    def __imod__(self, other):
        self.__obfuscate(self.__reveal() % other)
        return self

    # iterables 
    def __len__(self):
        return len(self.__reveal())
    def __getitem__(self,index):
        return self.__reveal()[index]
    def __setitem__(self,index,value):
        stored = self.__reveal()
        stored[index] = value
        self.__obfuscate(stored)
    def __delitem__(self,index):
        stored = self.__reveal()
        del(stored[index])
        self.__obfuscate(stored)
    def __iter__(self):
        self.__ptr = 0
        return self
    def __next__(self):
        if self.__ptr == len(self):
            raise StopIteration
        self.__ptr = self.__ptr + 1
        return self.__reveal()[self.__ptr-1]
    def __reversed__(self):
        for e in self.__reveal()[::-1]:
            yield e

def secure(value):
    return Hidden(value)

