# SNC
Secure Netcat

Netcat (the Unix nc command) is a powerful command line utility that is commonly used by systems administrators and adversaries alike. The netcat manpage has several examples, and you are encouraged to do a Web search for “netcat fun” to discover more.
While netcat has many command line options and lots of interesting functionality, this project focuses on the functionality described by its name: “net” and “cat.” The Unix cat command takes a file and prints it to STDOUT (or wherever STDOUT is redirected). For our purposes, think of netcat performing cat across a network. A client instance will receive input from STDIN and send it to a server instance. The server instance will receive network bytes and send it to STDOUT. As you might imagine, netcat provides no protection for the information as it is transmitted across the network.
The goal of this project is to provide confidentiality and integrity to this simple version of netcat. The standard way to add confidentiality and integrity to messages is through the use of cryptography. Encryption functions (e.g., AES) provide confidentiality. MAC functions (HMAC) provide integrity. As we know, there are different ways to combined encryption and MAC functions to provide both confidentiality and integrity: encrypt-and-MAC (E&M), encrypt-then-MAC (EtM), and MAC-then-encrypt (MtE). Out of these methods, E&M is insecure (sending the MAC of plaintext in the clear leaks information). Both EtM and MtE are used in a variety of cryptographic protocols, but only EtM reaches the highest definition of security. In addition to these ways of combining encryption and integrity, there are cipher modes that provide Authenticated Encryption (AE). These modes security combine encryption and MAC into the construction itself. The most notable of these modes is Galios Couter Mode (GCM). We will use AES-GCM for this project.
Program description. Our snc (secure netcat) command line program has the following command line options:

snc [-l] [--key KEY] [destination] [port]

The instance running on the client will read from STDIN and send AES-GCM protected data to the instance running on the server. The instance running on the server will read from the network, decrypt and authenticate the data, and write it to STDOUT. Both instances should terminate an EOF character is encountered, or if a keyboard interrupt (i.e., control-c) occurs. If the data fails to authenticate (e.g., the data was manipulated, or the keys were different), the server should terminate, reporting an error to STDERR.
The following is a sample execution:

[client]$ ./snc --key CSC574ISAWESOME server.add.ress 9999 < some-file.txt [server]$ ./snc --key CSC574ISAWESOME -l 9999 > some-file.txt

To be equivalent to the nc command, information entered in STDIN on the server should make its way to STDOUT on the client. To do this, we use multiple threads.
An sample execution with bi-directional flow is as follows:

[client]$ ./snc --key CSC574ISAWESOME server.add.ress 9999 < file1-in.txt > file2-out.txt [server]$ ./snc --key CSC574ISAWESOME -l 9999 > file1-out.txt < file2-in.txt


