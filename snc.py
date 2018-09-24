
'''
Secure Netcat(snc)
Developed with Python 3.7.0
Using multi-thread to implement bi-directional file transfer.
Using AES-256 in GCM mode from PyCryptodome library to encrypt and decrypt the data, and PBKDF2 is used to compute the key.
Argparse module is used to parse command line argument.
Something important you should know before running this program: 
**This program can only take piped files as input data, do not use keyboard to input data from the tty**
**No restriction for the output, you can redirect it to piped files or tty** 
**If you have any questions about this program, please contact me with the email provided**
Author: Yanchen Zhao
Email: yzhao47@ncsu.edu
'''
import os
import sys
import socket
import threading
import argparse
import json
import struct
from base64 import b64encode
from base64 import b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import unpad
from Cryptodome.Protocol.KDF import PBKDF2

class Ag: # class for create object which takes in the command line arguments
	pass

'''
encrypt function: AES_GCM_encrypt
arugument: 
data -- input data need to be encrypted
password -- the password used to generate key
return value: encoded json string include encrypt data, nonce, salt, and hash value  
'''
def AES_GCM_encrypt(data, password):
	salt = get_random_bytes(16) # salt for generate key
	key = PBKDF2(password=password, salt=salt, dkLen=32)
	cipher = AES.new(key, AES.MODE_GCM)
	cipher.update(salt)
	ciphertext, tag = cipher.encrypt_and_digest(data)
	json_k = ['nonce', 'salt', 'ciphertext', 'tag']
	json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce, salt, ciphertext, tag]]
	result = json.dumps(dict(zip(json_k, json_v)))
	return result.encode()

'''
decrypt function: AES_GCM_decrypt
argument: 
result -- json string need to be decoded 
password -- the password used to generate key
return value: if no error occur return plaintext, else output error message and exit program
'''
def AES_GCM_decrypt(result, password):
	try:
		b64 = json.loads(result)
		json_k = ['nonce', 'salt', 'ciphertext', 'tag']
		jv = {k:b64decode(b64[k]) for k in json_k}
		key = PBKDF2(password=password, salt=jv['salt'], dkLen=32)
		cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
		cipher.update(jv['salt'])
		plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
	except(ValueError, KeyError): # if fail to decrypt report an error to STDERR and exit
		sys.stderr.write("Incorrect decryption")
		return ''
	else:
		return plaintext

'''
Thread function for the client: client_thread
argument: 
Type -- thread for sending data or receiving data 
server_ip -- server's ip address
port:server's port number 
password -- the password used to generate key
return value: None
'''
def client_thread(Type, server_ip, port, password): 
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((server_ip, port)) # connect to server
		if Type == 'send':
			s.send(b'send thread') # let server know this is a thread for sending data
			data = s.recv(1024)
			if data == b'ready to receive': # server is ready to receive data
				while True:
					if sys.stdin.isatty(): # if no input file close the thread by send an EOF 
						line = ''.encode()
					else:
						line = sys.stdin.buffer.read(5000) # read the input file in binary mode and read 5000 bytes everytime
					encrypt_line = AES_GCM_encrypt(line, password) # encrypt data readed
					Package_size = sys.getsizeof(encrypt_line) # get the size of encrypt data
					s.send(struct.pack('!I', Package_size)) # send the size of encrypt data to server
					wait_ack = s.recv(1024) # wait for server until it received the size of encrypt data
					s.sendall(encrypt_line) # send all of the encrypt data readed for this time
					wait_ack = s.recv(1024) # wait for server to receive all of the encrypt data
					if not line: # if EOF encountered exit the thread
						break
				sys.stdin.close()
		else:
			s.send(b'receive thread') # let server know this is a thread for receiving data
			data = s.recv(1024)
			if data == b'ready to send': # server is ready to send data
				while True:
					size_data = s.recv(4) # receive the size of the upcoming data
					s.send(b'ack data size') # told server size of data is received
					if not size_data: 
						break
					package_size = struct.unpack('!I', size_data)
					package_size = package_size[0]
					package_data = ''.encode()
					while package_size > 0: # receive the data with a loop
						if package_size >= 1024:
							f_data = s.recv(1024)
							package_size = package_size - 1024
						else:
							f_data = s.recv(package_size)
							package_size = 0
						package_data = package_data + f_data
					s.send(b'ack data') # told server all sent data has been received
					content = AES_GCM_decrypt(package_data.decode(), password) # decrypt the data received 
					if not content: # if encountered EOF exit thread
						break
					sys.stdout.buffer.write(content) # write the decrypt data into STDOUT
				sys.stdout.close()
		s.close() # close the socket
		return
	except:	# catch the except if server disconnected and exit thread
		os._exit(0)

'''
Thread function for server: server_thread
argument:
sock -- server socket which connected with the client socket
addr -- client's address
password -- the password used to generate key 
return value: None
'''
def server_thread(sock, addr, password): # same logic as the client thread  
	try:
		data = sock.recv(1024)
		if data == b'send thread':
			sock.send(b'ready to receive')
			while True:
				size_data = sock.recv(4)
				sock.send(b'ack data size')
				if not size_data:
					break
				package_size = struct.unpack('!I', size_data)
				package_size = package_size[0]
				package_data = ''.encode()
				while package_size > 0:
					if package_size >= 1024:
						f_data = sock.recv(1024)
						package_size = package_size - 1024
					else:
						f_data = sock.recv(package_size)
						package_size = 0
					package_data = package_data + f_data
				sock.send(b'ack data')
				content = AES_GCM_decrypt(package_data.decode(), password)
				if not content:
					break
				sys.stdout.buffer.write(content)
			sys.stdout.close()
		else:
			sock.send(b'ready to send')
			while True:
				if sys.stdin.isatty():
					line = ''.encode()
				else:
					line = sys.stdin.buffer.read(5000)
				encrypt_line = AES_GCM_encrypt(line, password)
				Package_size = sys.getsizeof(encrypt_line)
				sock.send(struct.pack('!I', Package_size))
				sock.recv(1024)
				sock.sendall(encrypt_line)
				sock.recv(1024)
				if not line:
					break
			sys.stdin.close()
		sock.close()
		return
	except:
		os._exit(0)

'''
main function to generate the server or client: main
argument:
is_server -- decide if this is a server, if it is True means this is a server
password -- the password used to generate key
server_ip -- server's ip address
port -- server's port
return value: None
'''
def main(is_server, password, server_ip, port):
	try:
		if is_server: # if this is a server
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind(('0.0.0.0', port))
			s.listen(5)
			count = 0
			while count < 2:
				sock, addr = s.accept() # accept the connection from client
				if count == 0:
					t1 = threading.Thread(target=server_thread, args=(sock, addr, password)) # open a thread to deal with one of the client socket 
					t1.setDaemon(True) # set it as a daemon thread
					t1.start() # start the thread
				else:
					t2 = threading.Thread(target=server_thread, args=(sock, addr, password))
					t2.setDaemon(True)
					t2.start()
					while t2.isAlive() or t1.isAlive(): # exit only if both thread are closed
						pass
				count = count + 1
		else: # if this is a client
			t1 = threading.Thread(target=client_thread, args=('send', server_ip, port, password)) # open a thread to send data
			t2 = threading.Thread(target=client_thread, args=('receive', server_ip, port, password)) # open a thread to receive the data 
			t1.setDaemon(True)
			t2.setDaemon(True)
			t1.start()
			t2.start()
			while t1.isAlive() or t2.isAlive():
				pass
	except KeyboardInterrupt: # if control-C is pressed program will exit
		sys.exit()

'''
Parse the arguments from the command line and run the program
'''
if __name__ == '__main__':
	ag = Ag()
	parser = argparse.ArgumentParser(description = 'This is an advanced netcat provides confidentiality and integrity to users.')
	parser.add_argument('-l', action = 'store_true', help = 'listen mode', dest = 'is_server')
	parser.add_argument('--key', required = True, help = 'user\'s password used to produce key', metavar = 'KEY', dest = 'password')
	parser.add_argument('server_ip', nargs = '?', default = '', help = 'server\'s ip address', metavar = 'destination')
	parser.add_argument('port', type = int, help = 'server\'s port', metavar = 'port')
	parser.parse_args(namespace = ag)
	if ag.is_server == True and ag.server_ip != '':
		print('Error: Do not need destination or -l!')
		sys.exit()
	if ag.is_server == False and ag.server_ip == '':
		print('Error: destination or -l is needed!')
		sys.exit()
	main(ag.is_server, ag.password, ag.server_ip, ag.port)