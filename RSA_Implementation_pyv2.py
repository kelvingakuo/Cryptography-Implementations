import random
import sympy

class RSA(object):
	""" Implements RSA encryption
		Contains relevant attributes and functions for:
		1. Generation of private key
		2. Generation of public key
		3. Message encryption
		4. Message decryption
	"""
	def __init__(self):
		""" Initialises two huge random prime numbers, n, and m.
			Also generates the relevant public (e) and private (d) keys
		"""
		# Choose random primes between 500 and 1000
		# For larger primes, >=1024 bit, requests.get("https://2ton.com.au/getprimes/random/2048").content

		self.prime1 = sympy.randprime(500, 1000)
		self.prime2 = sympy.randprime(500, 1000)

		self.n = self.prime1 * self.prime2
		self.m = (self.prime1 - 1) * (self.prime2 - 1)

		# Choose e and d
		self.e = self.chooseE(self.m)
		self.d = self.eGCD(self.e, self.m)
		if(self.d < 0):
			self.d = self.d + self.m


	def chooseE(self, m):
		""" Iteratively choose e between 2 and m till gcd(e, m) == 1
			Params:
				m - (p - 1) * (q - 1)
		"""
		while True:
			e = random.randrange(2, m)
			gcd = self.GCD(e, m)
			
			if(gcd == 1):
				return e

	def GCD(self, a, b):
		""" Compute gcd of two numbers using Ecludiean algorithm
			Params:
				a, b - Integers
			Returns:
				gcd - The GCD
		"""
		if(b == 0):
			gcd = a
		else:
			gcd = self.GCD(b, a % b)

		return gcd


	def eGCD(self, a, b):
		""" Compute x to satisfy ax = 1 (mod b) i.e. get u and v so that au + xv = 1  using the extended Euclidean algorithm
			Params:
				a, b - Integers where gcd(a, b) == 1
			Returns:
				s0 - The computed value
		"""
		s0, s1 = 1, 0
		t0, t1 = 0, 1

		while(b != 0):
			q = a // b
			r = a % b
			a, b = b, r
			s = s0 - (q * s1)
			s0, s1 = s1, s
			t = t0 - (q * t1)
			t0, t1 = t1, t

		return s0

	def encrypt(self, msg):
		""" Returns an encrypted version of the ASCII version msg using the public key
			Params:
				msg - An alphanumeric string
			Returns:
				hashed - Encrypted message
		"""

		asciiVals = [ord(c) for c in msg]
		hashedVals = [(m ** self.e) % self.n for m in asciiVals ]
		hashed = ''.join([unichr(h).encode('utf-8') for h in hashedVals])

		return hashed
		


	def decrypt(self, hashedMsg):
		""" Returns the decrypted gibberish using the private key
			Params:
				hashedMsg - Encrypted info. Output of encrypt()
			Returns:
				msg - Decrypted message
		"""

		hashedVals = [ord(c) for c in hashedMsg.decode('utf-8')]
		msgVals = [(h ** self.d) % self.n for h in hashedVals]
		msg = ''.join([unichr(m).encode('utf-8') for m in msgVals])

		return msg



if __name__ == "__main__":
	rsa = RSA()

	msg = "Math + human ingenuity equal magic. #254"
	hashed = rsa.encrypt(msg)
	plaintxt = rsa.decrypt(hashed)

	print("The original message: {}\n".format(msg))
	print("The message after encryption: {}\n".format(hashed))
	print("The decrypted message: {}\n".format(plaintxt))