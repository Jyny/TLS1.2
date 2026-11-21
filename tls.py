import sys
import hmac

# TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
MAC_LEN = 20    # HMAC-SHA1
KEY_LEN = 16    # AES-128
BLOCK = 16      # AES block size == explicit IV length

CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA = 0x14, 0x15, 0x16, 0x17
CLIENT_HELLO, SERVER_HELLO, CLIENT_KEY_EXCHANGE = 0x01, 0x02, 0x10

def B2I(b):
	assert type(b) is bytes
	return int.from_bytes(b, byteorder='big')

def I2B(i, length):
	assert type(i) is int
	assert type(length) is int and length >= 0
	return int.to_bytes(i, length, byteorder='big')

def HMAC_SHA256(key, msg):
	return hmac.new(key, msg, 'sha256').digest()

def SYSTEM(command, stdin=None):
	from subprocess import Popen, PIPE
	proc = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
	stdout, stderr = proc.communicate(stdin)
	return stdout, stderr, proc.returncode

def RSA_DECRYPT(skfilename, ciphertext):
	assert type(skfilename) is str
	assert type(ciphertext) is bytes
	# `rsautl` is deprecated since OpenSSL 3.0 and prints a warning on stderr;
	# `pkeyutl` does the same PKCS#1 v1.5 decryption on OpenSSL 1.0+ / LibreSSL
	stdout, stderr, retcode = SYSTEM((
		'openssl', 'pkeyutl', '-decrypt', '-inkey', skfilename
	), ciphertext)
	assert retcode == 0, stderr
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
		'-K', secret_key.hex(),
		'-iv', ini_vector.hex()
	), ciphertext)
	assert retcode == 0, stderr
	return stdout

def parse_records(data):
	# RFC 5246 6.2.1: type(1) version(2) length(2) fragment(length)
	# Yields (seq, type, fragment); seq is the record sequence number used by
	# the MAC, counted from 0 again after ChangeCipherSpec (None before it)
	seq = None
	pos = 0
	while pos + 5 <= len(data):
		typ = data[pos]
		length = B2I(data[pos+3:pos+5])
		fragment = data[pos+5:pos+5+length]
		pos += 5 + length
		yield seq, typ, fragment
		if typ == CHANGE_CIPHER_SPEC:
			seq = 0
		elif seq is not None:
			seq += 1

def parse_handshakes(data):
	# Returns {msg_type: body} from the plaintext handshake records. Messages
	# may be coalesced into one record or split across several (RFC 5246 6.2.1),
	# so join every fragment before splitting on the 4-byte message headers.
	# Records after ChangeCipherSpec (the encrypted Finished) are skipped: their
	# first byte is ciphertext and could look like any msg_type.
	stream = b''.join(f for seq, typ, f in parse_records(data)
		if typ == HANDSHAKE and seq is None)
	messages = {}
	pos = 0
	while pos + 4 <= len(stream):
		msg_type = stream[pos]
		length = B2I(stream[pos+1:pos+4])
		messages[msg_type] = stream[pos+4:pos+4+length]
		pos += 4 + length
	return messages

def decrypt_app_data(data, mac_key, write_key):
	records = [(seq, f) for seq, typ, f in parse_records(data)
		if typ == APPLICATION_DATA]
	if not records:
		return b''
	# CBC decryption of a block only needs the previous ciphertext block, so
	# all records can go through one openssl call: inside each record the first
	# block is the explicit IV (RFC 5246 6.2.3.2) and is thrown away anyway,
	# hence whatever IV / preceding block it gets decrypted with doesn't matter.
	plain = AES128CBC_DECRYPT(write_key, bytes(BLOCK), b''.join(f for _, f in records))

	result = []
	pos = 0
	for seq, fragment in records:
		block = plain[pos+BLOCK:pos+len(fragment)]
		pos += len(fragment)

		# GenericBlockCipher: content | MAC | padding | padding_length
		pad_len = block[-1]
		assert block[-pad_len-1:] == bytes([pad_len]) * (pad_len + 1), 'bad padding'
		content = block[:-pad_len-1-MAC_LEN]
		mac = block[-pad_len-1-MAC_LEN:-pad_len-1]

		# RFC 5246 6.2.3.1: HMAC(seq_num + type + version + length + content)
		header = I2B(seq, 8) + bytes([APPLICATION_DATA, 3, 3]) + I2B(len(content), 2)
		expected = hmac.new(mac_key, header + content, 'sha1').digest()
		assert hmac.compare_digest(mac, expected), 'bad MAC (wrong keys?)'

		result.append(content)
	return b''.join(result)

def main():
	in1, in2, in3, out1, out2 = sys.argv[1:]
	with open(in1, 'rb') as f:
		cs_data = f.read()  # client-to-server
	with open(in2, 'rb') as f:
		sc_data = f.read()  # server-to-client

	clie_hs = parse_handshakes(cs_data)
	serv_hs = parse_handshakes(sc_data)

	# Hello body: version(2) random(32) ...
	clie_random = clie_hs[CLIENT_HELLO][2:34]
	serv_random = serv_hs[SERVER_HELLO][2:34]

	# ClientKeyExchange body: length(2) encrypted_pre_master_secret(length)
	cke = clie_hs[CLIENT_KEY_EXCHANGE]
	encrypted_pre_master_secret = cke[2:2+B2I(cke[:2])]
	pre_master_secret = RSA_DECRYPT(in3, encrypted_pre_master_secret)
	assert len(pre_master_secret) == 48

	# RFC 5246 8.1 / 6.3; TLS 1.2 CBC suites use explicit IVs, so the key block
	# holds only the MAC keys and the encryption keys
	master_secret = TLS_PRF(pre_master_secret, b'master secret', clie_random + serv_random, 48)
	key_block = TLS_PRF(master_secret, b'key expansion', serv_random + clie_random, 2 * (MAC_LEN + KEY_LEN))

	clie_write_MAC_key = key_block[:MAC_LEN]
	serv_write_MAC_key = key_block[MAC_LEN:2*MAC_LEN]
	clie_write_key = key_block[2*MAC_LEN:2*MAC_LEN+KEY_LEN]
	serv_write_key = key_block[2*MAC_LEN+KEY_LEN:]

	with open(out1, 'wb') as f:
		f.write(decrypt_app_data(cs_data, clie_write_MAC_key, clie_write_key))
	with open(out2, 'wb') as f:
		f.write(decrypt_app_data(sc_data, serv_write_MAC_key, serv_write_key))

if __name__ == '__main__':
	main()
