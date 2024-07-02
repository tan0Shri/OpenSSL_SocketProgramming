# OpenSSL_SocketProgramming
Here the programs attached demonstrates a simple SSL/TLS -based chat server in C using OpenSSL. The server listens for incoming multiple client connections, establishes secure communication using SSL/TLS, and broadcasts messages received from one client to all other clients.

Here, my written code will connect the server and clients in the same device. But to connect with different device, we need to specify some IP address to the server (server.c) code (IP address for your server device can be obtained by "ifconfg" command in linux terminal of that particular device) and put that same IP address to the client(client.c) code before the connect function. 

First run the "server.c" program and then only run the "clinet.c" program.
For more guidance to the run the codes succesfully please follow the file "Assignments description", though all the instructions are given for Linux based system only.
