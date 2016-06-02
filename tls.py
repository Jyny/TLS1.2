import sys

def B2I(b):
	assert type(b) is bytes
	return int.from_bytes(b, byteorder='big')

def I2B(i, length):
	assert type(i) is int
	assert type(length) is int and length >= 0
	return int.to_bytes(i, length, byteorder='big')

def HMAC_SHA256(key, msg):
	import hmac
	return hmac.new(key, msg, 'sha256').digest()

def SYSTEM(command, stdin=None):
	from subprocess import Popen, PIPE
	proc = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
	stdout, stderr = proc.communicate(stdin)
	return stdout, stderr, proc.returncode

def RSA_DECRYPT(skfilename, ciphertext):
	assert type(skfilename) is str
	assert type(ciphertext) is bytes
	stdout, stderr, retcode = SYSTEM((
		'openssl', 'rsautl', '-decrypt', '-inkey', skfilename
	), ciphertext)
	assert retcode == 0 and stderr == b''
	return stdout

def TLS_PRF(secret, label, seed, n_bytes):
	assert type(secret) is bytes
	assert type(label) is bytes
	assert type(seed) is bytes
	assert type(n_bytes) is int and n_bytes >= 0
	last_A = label + seed
	result = b''
	while len(result) < n_bytes:
		last_A = HMAC_SHA256(secret, last_A)
		result += HMAC_SHA256(secret, last_A + label + seed)
	return result[:n_bytes]

def AES128CBC_DECRYPT(secret_key, ini_vector, ciphertext):
	assert type(secret_key) is bytes and len(secret_key) == 16
	assert type(ini_vector) is bytes and len(ini_vector) == 16
	assert type(ciphertext) is bytes and len(ciphertext) % 16 == 0
	stdout, stderr, retcode = SYSTEM((
		'openssl', 'enc', '-aes-128-cbc', '-d', '-nopad',
		'-K', ''.join('%02x'%x for x in secret_key),
		'-iv', ''.join('%02x'%x for x in ini_vector)
	), ciphertext)
	assert retcode == 0 and stderr == b''
	return stdout

def main():
	in1, in2, in3, out1, out2 = sys.argv[1:]
	f1 = open(in1, 'rb') # client-to-server
	f2 = open(in2, 'rb') # server-to-client
	cs_data = f1.read()
	sc_data = f2.read()
	f1.close()
	f2.close()

	clie_app_data = []
	serv_app_data = []

	# client to server demsg
	while len(cs_data) > 0:
		typ, ver1, ver2, len1, len2 = cs_data[:5]
		length = (len1 * 256) + len2
		fragment = cs_data[5:5+length]

		if typ == 0x14:
			clie_change_cipher_spec = fragment

		elif typ == 0x15:
			clie_alert = fragment

		elif typ == 0x16:
			if fragment[0] == 0x01:
				clie_hello = fragment
			elif fragment[0] == 0x10:
				clie_key_exchange = fragment
			else:
				clie_finished = fragment

		elif typ == 0x17:
			clie_app_data.append(fragment)

		else:
			print("client error type")

		cs_data = cs_data[5+length:]

	# server to client demsg
	while len(sc_data) > 0:
		typ, ver1, ver2, len1, len2 = sc_data[:5]
		length = (len1 * 256) + len2
		fragment = sc_data[5:5+length]

		if typ == 0x14:
			serv_change_cipher_spec = fragment

		elif typ == 0x15:
			serv_alert = fragment

		elif typ == 0x16:
			if fragment[0] == 0x02:
				serv_hello = fragment
			elif fragment[0] == 0x0B:
				serv_certificate = fragment
			elif fragment[0] == 0x0E:
				serv_hello_done = fragment
			else:
				serv_finished = fragment

		elif typ == 0x17:
			serv_app_data.append(fragment)

		else:
			print("server error type")

		sc_data = sc_data[5+length:]

	clie_random = clie_hello[6:38]
	#print("clie_random:",clie_random.hex())

	serv_random = serv_hello[6:38]
	#print("serv_random:",serv_random.hex())

	# TLS_PRF
	encrypted_pre_master_secret = clie_key_exchange[6:]
	pre_master_secret = RSA_DECRYPT(in3,encrypted_pre_master_secret)
	master_secret = TLS_PRF(pre_master_secret, b'master secret', clie_random+serv_random, 48)
	key_expansion = TLS_PRF(master_secret, b'key expansion', serv_random+clie_random, 104)

	clie_write_MAC_key = key_expansion[:20]
	serv_write_MAC_key = key_expansion[20:40]
	clie_write_key = key_expansion[40:56]
	serv_write_key = key_expansion[56:72]
	clie_write_iv = key_expansion[72:88]
	serv_write_iv = key_expansion[88:104]

	clie_result = b''
	serv_result = b''

	# decrypt client data
	for each in clie_app_data:
		temp = AES128CBC_DECRYPT(clie_write_key, clie_write_iv ,each)
		temp = temp[16:]
		temp = temp[:-temp[-1]-1]
		temp = temp[:-20]
		clie_result += temp

	# decrypt server data
	for each in serv_app_data:
		temp = AES128CBC_DECRYPT(serv_write_key, serv_write_iv ,each)
		temp = temp[16:]
		temp = temp[:-temp[-1]-1]
		temp = temp[:-20]
		serv_result += temp

	#print("client", clie_result)
	#print("server", serv_result)

	f1 = open(out1, 'rb')
	f2 = open(out2, 'rb')
	client = f1.read()
	server = f2.read()

	if clie_result==client and serv_result==server:
		print("OK")
	else:
		print("NO OK")


if __name__ == '__main__':
	main()
