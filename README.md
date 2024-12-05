# cis525-Project-7

### Josh Caldwell, Iain Cline, Regan Hazell

This repository contains C code that implements the Chat Room application described in Assignment 7. This Multiple chat topics can be established within the directory server, and each topic (server) can be connected to through chatClients that can send a receive messages through the server. The directory-server-client connections use non-blocking I/O and are secured using GnuTLS 1.3 Certificate Authorities

1. Clone repository into a directory in cslinux.cs.ksu.edu. 
`$ git clone https://github.com/joCaldwell/cis525-Project-7.git`
update 'inet.h' with your appropriate IP for either couger or viper and run `make` in the terminal to build the executables

2. In your terminal, run `$ ./directoryServer5 &` first to beign the server directory. If you get an error saying "port is already in use" you may need to adjust your port number in 'inet.h'

3. Then, in seperate terminals run `$ ./chatServer5 "<topic_name>" <port_number>` to begin running a chat room. Both parameters should be unique, and the port number should be between 40000 and 65535.

4. To start a chat client, in a seperate terminal run `$ ./chatClient5` and from there you'll be given more direction on how to join a chat room and how to chat