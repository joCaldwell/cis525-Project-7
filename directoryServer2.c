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

struct server{
	char 				topic[MAX];
	int 				sock, has_topic;
	struct sockaddr_in 	serv_addr;
	uint16_t 			port;
	LIST_ENTRY(server) 	entries;
};

int main()
{
	int							sockfd, newsockfd, j;
	uint16_t 					port;
	unsigned int				servlen;
	char						command, s[MAX], messageToSend[MAX], message[MAX];
	LIST_HEAD(serv_list,server) servHead;
	fd_set 						readset;
	struct sockaddr_in 			cli_addr, serv_addr, dir_serv_addr;
	struct server 				*serv, *innerServ;	

	/* Initialze the list of servers */
	LIST_INIT(&servHead);

	/* initialize server variables */
	serv = malloc(sizeof(struct server));
	innerServ = malloc(sizeof(struct server));

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
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family 		= AF_INET;
	dir_serv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	dir_serv_addr.sin_port 			= htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("server: can't bind local address");
		exit(1);
	}

	listen(sockfd, 5);

	servlen = sizeof(serv_addr);

	for (;;) {
		FD_ZERO(&readset);
		/* Set the listening socket in the readset */
		FD_SET(sockfd, &readset);
		/* Set the open clients in the readset */
		int maxSockNum = sockfd;
		LIST_FOREACH(serv, &servHead, entries) {
			FD_SET(serv->sock, &readset);
			if (serv->sock > maxSockNum) maxSockNum = serv->sock;
		}

		/* Select statement (hangs until a socket is ready) */
		if ((j = select(maxSockNum+1, &readset, NULL, NULL, NULL)) > 0){ 
			/* Check if the listening socket can be read */
			if (FD_ISSET(sockfd, &readset)) {
				/* accept the connection */
				servlen = sizeof(cli_addr);
				if ((newsockfd = accept(sockfd, (struct sockaddr *) &serv_addr, &servlen)) < 0) {
					/* something bad happend in the connection. Don't create client */
				} else {
					/* add the socket to the client list */
					struct server *newServ = malloc(sizeof(struct server));
					memset(newServ->topic, '\0', MAX);
					newServ->has_topic = 0;
					newServ->sock = newsockfd;
					newServ->serv_addr = serv_addr;
					LIST_INSERT_HEAD(&servHead, newServ, entries);
				}

			}

			/* Read from the rest of the ready sockets */
			struct server *servToRemove = NULL;
			LIST_FOREACH(serv, &servHead, entries) {
				if (FD_ISSET(serv->sock, &readset)) {
					/* Read the message */
					if ((read(serv->sock, s, MAX)) <= 0) {
						/* Something went wrong / Client has disconnected */
						servToRemove = serv;
						if (serv->has_topic) {
							printf("Chat room %s has left.\n", serv->topic);
						}

					} else {
						/* There is a valid message, proccess it */
						j = sscanf(s, "%c %hu %[^\n]", &command, &port, message);

						memset(messageToSend, 0, MAX); // clear the buffer
						// Check for formatting issues
						if (j <= 0) {
							snprintf(messageToSend, MAX, "f failed parsing");
							write(serv->sock, messageToSend, MAX);
							break;
						} else if (j == 1 && command != 'c') {
							// Only 1 char should be c, but it isn't here
							snprintf(messageToSend, MAX, "f bad format (expected `c` got `%c`)", command);
							write(serv->sock, messageToSend, MAX);
							break;
						} else if (j == 3 && command != 's') {
							snprintf(messageToSend, MAX, "f bad format (expected `s <port> <topic>` got `%c %hu %s`)", command, port, message);
							write(serv->sock, messageToSend, MAX);
							break;
						}
						switch(command) { // Command tells us if it is a client or server
							case 's':
								int duplicate = 0;
								LIST_FOREACH(innerServ, &servHead, entries) {
									if ((innerServ->sock != serv->sock) && innerServ->has_topic) {
										/* innerServ is a registered chat room */
										if (strncmp(innerServ->topic, message, MAX) == 0) {
											duplicate = 1;
											break;
										}
									}
								}

								if (duplicate) {
									snprintf(messageToSend, MAX, "f A server already has the name: %s", message);
									write(serv->sock, messageToSend, MAX);
									break;
								}

								/* Server, set topic and port (it is now registered) */
								memcpy(serv->topic, message, MAX);
								serv->has_topic = 1;
								serv->port = port;

								// Tell the server that the process was successful
								memset(messageToSend, 0, MAX); // clear the buffer
								snprintf(messageToSend, MAX, "s");
								write(serv->sock, messageToSend, MAX);
								break;

							case 'c':
								/* Client, give list of servers */
								LIST_FOREACH(innerServ, &servHead, entries) {
									if (innerServ->sock != serv->sock && innerServ->has_topic) {
										/* innerServ is a registered chat room */
										memset(messageToSend, 0, MAX); // clear the buffer
										snprintf(messageToSend, MAX, "%s %hu %s", inet_ntoa(serv_addr.sin_addr), innerServ->port, innerServ->topic);
										write(serv->sock, messageToSend, MAX);
									}
								}
								/* Remove the client from the directory server because it is not a chat room */
								servToRemove = serv;
								break;

							default:
								memset(messageToSend, 0, MAX); // clear the buffer
								snprintf(messageToSend, MAX, "%c is not a valid option\n", command);
								write(serv->sock, messageToSend, MAX);
								break;
						}
					}
				}
			}
			/* can't remove a list element in the LIST_FOREACH (Known bug) */
			if (servToRemove != NULL) {
				/* Remove the client from the list */
				close(servToRemove->sock);
				LIST_REMOVE(servToRemove, entries);
				/* Free the memory for the server */
				free(servToRemove);
			}

		}
	}
	/* Cleanup */
	LIST_FOREACH(serv, &servHead, entries) {
		close(serv->sock);
		free(serv);
	}
	free(innerServ);
	close(sockfd);
	return 0;
}
