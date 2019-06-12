from bitarray import bitarray
from math import floor
from math import sin
import os
import struct

# Reference : https://tools.ietf.org/html/rfc1321
	# https://en.wikipedia.org/wiki/MD5#Pseudocode
class MD5(object):
	""" Implements salted MD5 hashing
	Contains relevant attributes and functions for:
	1. Message convertion to binary
	2. Message padding
	3. Hash initialisation and updating
	"""
	def __init__(self):
		""" Initialises the hash's 4 32-bit words and updation functions
		"""
		# Hash's initial 4 32-bit words as per the origi paper
		self.A = 0x67452301
		self.B = 0xEFCDAB89
		self.C = 0x98BADCFE
		self.D = 0x10325476

		# The functions to update the hash, in lambda notation
		self.fnF = lambda b, c, d: (b & c) | (~b & d)
		self.fnG = lambda b, c, d: (b & d) | (c & ~d)
		self.fnH = lambda b, c, d: b ^ c ^ d
		self.fnI = lambda b, c, d: c ^ (b | ~d)

		# A required T-table
		self.T = [floor((2 ** 32) * abs(sin(i + 1))) for i in range(64)]
		# Rotate x left n bits
		self.rotateLeft = lambda x, n: (x << n) | (x >> (32 - n))
		# Mod. Again
		self.modAdd = lambda a, b: (a + b) % (2 ** 32)


	def convertString(self, plaintxt):
		""" Prepend a random salt then convert string to bit array
			Params:
				plaintxt - The string
			Returns:
				saltedBits - Salted string as bits
		"""
		salt = os.urandom(128).encode('base-64')
		saltedStr = "{}{}".format(salt, plaintxt)
		self.plainSalted =  saltedStr

		saltedBits = bitarray(endian="big")
		saltedBits.frombytes(saltedStr.encode("utf-8"))

		return saltedBits
		
		
	def padString(self, mbits):
		""" Pads the string till length = 448 mod 512 i.e. till 64bits less than a multiple of 512... How? Appends '1' then enough '0's. 
			Then appends the msg's original length mod 2^64
			Params:
				mbits - Original array of bits
			Returns:
				mbits - The bits in the needed length
		"""
		mbits.append(1)
		while mbits.length() % 512 != 448:
			mbits.append(0)

		bitarray(mbits, endian="little") #Required
		self.mbitsLess64 = mbits.copy()

		txtLen = (len(self.plainSalted) * 8) % (2 ** 64)

		txtLenBits = bitarray(endian="little")
		txtLenBits.frombytes(struct.pack("<Q", txtLen))

		mbits.extend(txtLenBits)

		return mbits


	def performMathemagic(self, paddedBits):
		""" Update the hash with four rounds each with 16 operations.
			Consumes paddedBits in 32-bit chunks
			Params:
				paddedBits - The padded bits of the plaintext
			Returns:
				hexDigest - The hash
		"""
		chunksCount = paddedBits.length() / 32

		for i in range(chunksCount / 16):
			start = i * 512
			X = [paddedBits[start + (x * 32) : start + (x * 32) + 32] for x in range(16)]
			X = [struct.unpack("<L", word)[0] for word in X]

			# Repetition because it's prettier (?)
			A = self.A
			B = self.B
			C = self.C
			D = self.D

			F = self.fnF
			G = self.fnG
			H = self.fnH
			I = self.fnI

			for j in range(64):
				if 0 <= j <= 15:
					k = j
					s = [7, 12, 17, 22]
					temp = F(B, C, D)
				elif 16 <= j <= 31:
					k = ((5 * j) + 1) % 16
					s = [5, 9, 14, 20]
					temp = G(B, C, D)
				elif 32 <= j <= 47:
					k = ((3 * j) + 5) % 16
					s = [4, 11, 16, 23]
					temp = H(B, C, D)
				elif 48 <= j <= 63:
					k = (7 * j) % 16
					s = [6, 10, 15, 21]
					temp = I(B, C, D)

		
				temp = self.modAdd(temp, X[k])
				temp = self.modAdd(temp, self.T[j])
				temp = self.modAdd(temp, A)
				temp = int(temp)
				temp = self.rotateLeft(temp, s[j % 4])
				temp = self.modAdd(temp, B)

				A = D
				D = C
				C = B
				B = temp

			# Update hash
			self.A = self.modAdd(self.A, A)
			self.B = self.modAdd(self.B, B)
			self.C = self.modAdd(self.C, C)
			self.D = self.modAdd(self.D, D)

		# Append the parts and generate hex
		A = struct.unpack("<I", struct.pack(">I", self.A))[0]
		B = struct.unpack("<I", struct.pack(">I", self.B))[0]
		C = struct.unpack("<I", struct.pack(">I", self.C))[0]
		D = struct.unpack("<I", struct.pack(">I", self.D))[0]

		hexDigest = "{}{}{}{}".format(hex(A), hex(B), hex(C), hex(D))

		return hexDigest 

	def gen_hash(self, msg):
		""" Combines the MD5 steps to update the hash.
			Params:
				msg - String to hash
			Returns:
				saltedHash - Final hash
		"""
		digest = self.performMathemagic(self.padString(self.convertString(msg)))
		return digest


if __name__ == "__main__":
	md5 = MD5()

	msg1 = "A TRUNCATION O"
	msg2 = "Veery long collection of words, /*#, and 234323."
	
	hash1 = md5.gen_hash(msg1)
	hash2 = md5.gen_hash(msg2)

	print("The first string: {}".format(msg1))
	print("First message hashed: {}\n\n".format(hash1))

	print("The second string: {}".format(msg2))
	print("Second string hashed: {}".format(hash2))

