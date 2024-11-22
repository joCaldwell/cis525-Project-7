#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"

struct client {
	char 				name[MAX], to[MAX], fr[MAX];
	char				*toptr, *frptr;
	int 				has_name, sock, has_message_to_send;
	LIST_ENTRY(client) 	entries;
};

int main(int argc, char **argv)
{
	char							command, s[MAX], topic[MAX], message[MAX], messageToSend[MAX];
	int								sockfd, newsockfd, n, j;
	uint16_t						port;
	unsigned int					clilen;
	LIST_HEAD(client_list, client) 	clientHead;
	fd_set 							readset, writeset;
	struct sockaddr_in				cli_addr, serv_addr, dir_serv_addr;
	struct client 					*cli, *innerCli, *cliToRemove;	

	/* Initialze the list of clients */
	LIST_INIT(&clientHead);

	/* check number of command line arguments */
	if (argc < 3) {
		perror("server: not enough arguments supplied.\nRun with: `chatserver2 \"<topic>\" <port>`");
		exit(1);
	}

	/* Set up the address of the directory server to be contacted. */
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family			= AF_INET;
	dir_serv_addr.sin_addr.s_addr		= inet_addr(SERV_HOST_ADDR);
	dir_serv_addr.sin_port				= htons(SERV_TCP_PORT);

	/* assign port number and topic */
	memset(topic, 0, MAX); // clear the buffer
	snprintf(topic, MAX, "%s", argv[1]);
	if ((j = sscanf(argv[2], "%hu", &port)) != 1) {
		perror("server: port read was unsucessfull (Be sure the second argument is a valid port number)");
		exit(1);
	}

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}

	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	serv_addr.sin_port			= htons(port);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		exit(1);
	}

	/* Connect to the directory server. */
	if (connect(sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("server: can't connect to directory server");
		exit(1);
	} 

	/* Send port number and topic to the directory server to register it */
	memset(messageToSend, 0, MAX); // clear the buffer
	snprintf(messageToSend, MAX, "s %hu %s", port, topic);
	write(sockfd, messageToSend, MAX);
	// Get verification from directory that registering was successfull
	if (read(sockfd, s, MAX) < 0) {
		perror("Failed to read verification from server");
		exit(1);
	}

	memset(message, 0, MAX); // clear the buffer
	// Check message from Directory server (first char 's': success, 'f': fail)
	j = sscanf(s, "%c %[^\n]", &command, message);
	if (j <= 0) {
		perror("Failed to read verification from server");
		exit(1);
	} else if (j == 1) {
		// Only one character was sent, if it was 's' then verification was successful
		if (command != 's') {
			perror("Failed to read verification from server");
			exit(1);
		}
	} else if (j == 2) {
		// Both arguments were supplied, check the values
		if (command == 'f') {
			// Verifiaction failed print error message from directory
			printf("%s\n", message);
			exit(1);
		} else if (command != 's') {
			perror("Failed to read verification from server");
			exit(1);
		}
	}


	/* RESET TO LISTEN FOR CLIENTS */
	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}

	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	serv_addr.sin_port			= htons(port);
 
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) { 
		perror("server: can't bind local address"); 
		exit(1); 
	} 
 
	listen(sockfd, MAX_CLIENTS);

	/* Main Loop for the program*/
	for (;;) {
		FD_ZERO(&readset); FD_ZERO(&writeset);
		/* Set the listening socket in the readset */
		FD_SET(sockfd, &readset);
		/* Set the open clients in the readset */
		int maxSockNum = sockfd;
		LIST_FOREACH(cli, &clientHead, entries) {
			FD_SET(cli->sock, &readset);
			FD_SET(cli->sock, &writeset);
			if (cli->sock > maxSockNum) maxSockNum = cli->sock;
		}

		/* Select statement (hangs until a socket is ready) */
		if ((j = select(maxSockNum+1, &readset, &writeset, NULL, NULL)) > 0){ 

			/* Check if the listening socket can be read */
			if (FD_ISSET(sockfd, &readset)) {
				/* accept the connection */
				clilen = sizeof(cli_addr);
				if ((newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen)) < 0) {
					/* something bad happend in the connection. Don't create client */
				} else {
					/* Set new socket to non blocking */
					int val = fcntl(newsockfd, F_GETFL, 0);
					fcntl(newsockfd, F_SETFL, val | O_NONBLOCK);

					/* add the socket to the client list */
					struct client *newCli = malloc(sizeof(struct client));
					memset(newCli->name, '\0', MAX);
					newCli->has_name = 0;
					newCli->sock = newsockfd;
					newCli->toptr = newCli->to;
					newCli->frptr = newCli->fr;
					LIST_INSERT_HEAD(&clientHead, newCli, entries);
				}

			}

			/* Reading messages*/
			cliToRemove = NULL;
			LIST_FOREACH(cli, &clientHead, entries) {
				if (FD_ISSET(cli->sock, &readset)) {
					/* Read the message */
					if (n = read(cli->sock, cli->frptr, &(cli->fr[MAX])) < 0) {
						if (errno != EWOULDBLOCK) {
							perror("read error on socket");
							cliToRemove = cli;
							break;
						}
					} else if (0 == n) {
						fprintf(stderr, "%s:%d: EOF on socket\n", __FILE__, __LINE__);
						if (cli->has_name) {
							snprintf(messageToSend, MAX, "%s has left the chat", cli->name);

							LIST_FOREACH(innerCli, &clientHead, entries) {
								/* Dont send to current client and only tell people who are in the chat. */
								if (innerCli->sock != cli->sock && innerCli->has_name) {
									strncpy(innerCli->to, messageToSend, MAX);
									innerCli->has_message_to_send = 1;
								}
							}
						}
						cliToRemove = cli;

					/* There is something to be read now */
					} else {						
						cli->frptr += n;
						if (cli->frptr < &(cli->fr[MAX])) {
							// Don't proccess the message until it is fully read.
							break;
						}

						/* Reset the frptr */
						cli->frptr = cli->fr;

						// The message should be fully read by now.
						if (sscanf(cli->fr, "%c %[^\n]", &command, message) != 2) {
							memset(messageToSend, 0, MAX); // clear the buffer
							snprintf(messageToSend, MAX, "Bad format");
							strncpy(cli->to, messageToSend, MAX);
							cli->has_message_to_send = 1;
							break;
						}

						switch(command) {

							case 'n':
								/* set or change name */
								int isFirst = 1; // Assume first, check if not
								int isDuplicate = 0; // Assume not a duplicate name, check if it is

								/* Check for a duplicate name */
								LIST_FOREACH(innerCli, &clientHead, entries) {
									if (innerCli->name != NULL && strncmp(innerCli->name, message, MAX) == 0) {
										isDuplicate = 1;
										break;
									}
								}

								/* The name alread exists, don't set it for this user. */
								if (isDuplicate) {
									memset(messageToSend, 0, MAX); // clear the buffer
									snprintf(messageToSend, MAX, "The name %s is already in the chat. Try Again\n", message);
									strncpy(cli->to, messageToSend, MAX);
									cli->has_message_to_send = 1;
									break;
								}

								/* Check if the user is the first on the server */
								LIST_FOREACH(innerCli, &clientHead, entries) {
									if (innerCli->sock != cli->sock && innerCli->name != NULL) {
										isFirst = 0;
										break;
									}
								}

								memset(messageToSend, 0, MAX); // clear the buffer
								if (isFirst) {
									/* the user is the first, tell them. */
									if (cli->has_name == 0) {
										snprintf(messageToSend, MAX, "Hello %s, You are the first user to join the chat\n", message);
									} else {
										snprintf(messageToSend, MAX, "Hello %s, You are the only user in the chat\n", message);
									}									
									strncpy(cli->to, messageToSend, MAX);
									cli->has_message_to_send = 1;

								} else {
									if (cli->has_name) {
										snprintf(messageToSend, MAX, "%s has changed name to %s", cli->name, message);
									} else {
										snprintf(messageToSend, MAX, "%s has joined the chat", message);
									}
									LIST_FOREACH(innerCli, &clientHead, entries) {
										/* Dont send to current client and only tell people who are in the chat. */
										if (innerCli->sock != cli->sock && innerCli->has_name) {
											strncpy(innerCli->to, messageToSend, MAX);
											innerCli->has_message_to_send = 1;
										}
									}
								}
								/* set the clients name */
								memcpy(cli->name, message, MAX);
								cli->has_name = 1;
								break;

							case 's':
								if (cli->name == NULL) {
									/* The client has not yet fully joined. */
									memset(messageToSend, 0, MAX); // clear the buffer
									snprintf(messageToSend, MAX, "You must first enter a name to chat! (`n <name>`)\n");
									strncpy(cli->to, messageToSend, MAX);
									cli->has_message_to_send = 1;
									break;
								}

								/* send the received message to all clients */
								memset(messageToSend, 0, MAX); // clear the buffer
								snprintf(messageToSend, MAX, "%s: %s", cli->name, message); // If name is long then the message will get cut off. Only 100 characters are possible to send here.
								LIST_FOREACH(innerCli, &clientHead, entries) {
									if (innerCli->sock != cli->sock) {
										strncpy(innerCli->to, messageToSend, MAX);
										innerCli->has_message_to_send = 1;
									}
								}
								break;

							default:
								memset(messageToSend, 0, MAX); // clear the buffer
								snprintf(messageToSend, MAX, "%c is not a valid option\n", command);
								strncpy(cli->to, messageToSend, MAX);
								cli->has_message_to_send = 1;
								break;
						}
					}
				}
			}

			/* Sending messages*/
			LIST_FOREACH(cli, &clientHead, entries) {
				if (FD_ISSET(cli->sock, &writeset) && cli->has_message_to_send) {
					if ( (n = write(cli->sock, cli->toptr, MAX)) < 0) {
						if (errno != EWOULDBLOCK) {
							perror("read error on socket");
							cliToRemove = cli;
							break;
						}
					/* There is a valid message */
					} else {
						cli->toptr += n;
						if (cli->toptr >= &(cli->to[MAX])) {
							// Reset the to buffer after writing it all.
							cli->toptr = cli->to;
							cli->has_message_to_send = 0;
						}
					}
				}
			}



			/* can't remove a list element in the LIST_FOREACH (Known bug) */
			if (cliToRemove != NULL) {
				close(cliToRemove->sock);
				/* Remove the client from the list */
				LIST_REMOVE(cliToRemove, entries);
				free(cliToRemove);
			}
		}
	}

	/* Cleanup */
	LIST_FOREACH(cli, &clientHead, entries) {
		close(cli->sock);
		free(cli);
	}
	free(innerCli);
	close(sockfd);
	return 0;
}