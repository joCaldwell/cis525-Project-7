#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "inet.h"
#include "common.h"

#define DIRECTORY_SERVER_CERT "certs/directory-server-cert.crt"
#define DIRECTORY_SERVER_KEY "certs/directory-server-key.pem"

struct server{
	char 				topic[MAX], to[MAX], fr[MAX];
	char 				*toptr, *frptr;
	int 				sock, has_topic, has_message_to_send, send_servers_list;
	struct sockaddr_in 	serv_addr;
	uint16_t 			port;
	LIST_ENTRY(server) 	entries;
	SSL 				*ssl;
};

int main()
{
	int							sockfd, newsockfd, j, n;
	uint16_t 					port;
	unsigned int				servlen;
	char						command, s[MAX], messageToSend[MAX], message[MAX];
	LIST_HEAD(serv_list,server) servHead;
	fd_set 						readset, writeset;
	struct sockaddr_in 			cli_addr, serv_addr, dir_serv_addr;
	struct server 				*serv, *innerServ, *servToRemove;
	SSL_CTX 					*ctx;

	/* Initialze the list of servers */
	LIST_INIT(&servHead);

	/* openssl initialization */
	SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the server's certificate
    if (SSL_CTX_use_certificate_file(ctx, DIRECTORY_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
		perror("Error loading server certificate");
        exit(EXIT_FAILURE);
    }

    // Load the server's private key
    if (SSL_CTX_use_PrivateKey_file(ctx, DIRECTORY_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
		perror("Error loading server private key");
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

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

	for (;;) {
		FD_ZERO(&readset); FD_ZERO(&writeset);
		/* Set the listening socket in the readset */
		FD_SET(sockfd, &readset);
		/* Set the open clients in the readset */
		int maxSockNum = sockfd;
		LIST_FOREACH(serv, &servHead, entries) {
			FD_SET(serv->sock, &readset);
			FD_SET(serv->sock, &writeset);
			if (serv->sock > maxSockNum) maxSockNum = serv->sock;
		}

		/* Select statement (hangs until a socket is ready) */
		if ((j = select(maxSockNum+1, &readset, &writeset, NULL, NULL)) > 0){ 

			/* Check if the listening socket can be read */
			if (FD_ISSET(sockfd, &readset)) {
				/* accept the connection */
				servlen = sizeof(serv_addr);
				if ((newsockfd = accept(sockfd, (struct sockaddr *) &serv_addr, &servlen)) < 0) {
					/* something bad happend in the connection. Don't create client */
				} else {
					/* Set socket to non blocking */
					int val = fcntl(newsockfd, F_GETFL, 0);
					fcntl(newsockfd, F_SETFL, val | O_NONBLOCK);

					/* create new server */
					struct server *newServ = malloc(sizeof(struct server));

					newServ->ssl = SSL_new(ctx);
					SSL_set_fd(newServ->ssl, newsockfd);

					/* SSL handshake with the server/client */
					int handshake_result, err;
					while ((handshake_result = SSL_accept(newServ->ssl)) <= 0) {
						err = SSL_get_error(newServ->ssl, handshake_result);
						if ((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE)) {
							ERR_print_errors_fp(stderr);
							close(newsockfd);
							SSL_free(newServ->ssl);
							printf("Handshake failed\n");
						}
					}
					printf("Handshake successful\n");

					/* initialize server variables */
					memset(newServ->topic, '\0', MAX);
					newServ->has_topic = 0;
					newServ->has_message_to_send = 0;
					newServ->send_servers_list = 0;
					newServ->sock = newsockfd;
					newServ->serv_addr = serv_addr;
					newServ->toptr = newServ->to;
					newServ->frptr = newServ->fr;

					/* add the socket to the client list */
					LIST_INSERT_HEAD(&servHead, newServ, entries);
				}

			}

			/* Reading messages from the ready sockets */
			servToRemove = NULL;
			LIST_FOREACH(serv, &servHead, entries) {
				if (FD_ISSET(serv->sock, &readset)) {
					/* Read the message */
					if ( (n = SSL_read(serv->ssl, serv->frptr, &(serv->fr[MAX]) - serv->frptr)) < 0) {
						int err = SSL_get_error(serv->ssl, n);
						if (errno != EWOULDBLOCK) {
							perror("read error on socket");
							servToRemove = serv;
							break;
						}
					} else if (0 == n) {
						fprintf(stderr, "%s:%d: EOF on socket\n", __FILE__, __LINE__);
						if (serv->has_topic) {
							printf("Chat room %s has left.\n", serv->topic);
						}
						servToRemove = serv;

					/* There is a valid message */
					} else {
						serv->frptr += n;
						if (serv->frptr < &(serv->fr[MAX])) {
							// Don't proccess the message until it is fully read.
							break;
						}

						/* Reset the frptr */
						serv->frptr = serv->fr;

						j = sscanf(serv->frptr, "%c %hu %[^\n]", &command, &port, message);

						memset(messageToSend, 0, MAX); // clear the buffer
						// Check for formatting issues
						if (j <= 0) {
							snprintf(messageToSend, MAX, "f failed parsing");
							strncpy(serv->to, messageToSend, MAX);
							serv->has_message_to_send = 1;
							break;
						} else if (j == 1 && command != 'c') {
							// Only 1 char should be c, but it isn't here
							snprintf(messageToSend, MAX, "f bad format (expected `c` got `%c`)", command);
							strncpy(serv->to, messageToSend, MAX);
							serv->has_message_to_send = 1;
							break;
						} else if (j == 3 && command != 's') {
							snprintf(messageToSend, MAX, "f bad format (expected `s <port> <topic>` got `%c %hu %s`)", command, port, message);
							strncpy(serv->to, messageToSend, MAX);
							serv->has_message_to_send = 1;
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
									strncpy(serv->to, messageToSend, MAX);
									serv->has_message_to_send = 1;
									break;
								}

								/* Server, set topic and port (it is now registered) */
								memcpy(serv->topic, message, MAX);
								serv->has_topic = 1;
								serv->port = port;

								fprintf(stderr, "%s:%d: server topic `%s` is regestered on port %d\n", __FILE__, __LINE__, serv->topic, serv->port);

								// Tell the server that the process was successful
								memset(messageToSend, 0, MAX); // clear the buffer
								snprintf(messageToSend, MAX, "s");
								strncpy(serv->to, messageToSend, MAX);
								serv->has_message_to_send = 1;
								break;

							case 'c':
								/* Client, give list of servers */
								LIST_FOREACH(innerServ, &servHead, entries) {
									// if (innerServ->sock != serv->sock && innerServ->has_topic) {
									// 	printf("Sending server %s to client\n", innerServ->topic);
									// 	/* innerServ is a registered chat room */
									// 	memset(messageToSend, 0, MAX); // clear the buffer
									// 	snprintf(messageToSend, MAX, "%s %hu %s", inet_ntoa(serv_addr.sin_addr), innerServ->port, innerServ->topic);
									// 	strncpy(serv->to, messageToSend, MAX);
									// 	serv->has_message_to_send = 1;
									// }
								}
								serv->has_message_to_send = 1;
								serv->send_servers_list = 1;

								/* Remove the client from the directory server because it is not a chat room */
								servToRemove = serv;
								break;

							default:
								memset(messageToSend, 0, MAX); // clear the buffer
								snprintf(messageToSend, MAX, "%c is not a valid option\n", command);
								strncpy(serv->to, messageToSend, MAX);
								serv->has_message_to_send = 1;
								break;
						}
					}
				}
			}

			/* Sending messages*/
			LIST_FOREACH(serv, &servHead, entries) {
				if (FD_ISSET(serv->sock, &writeset) && serv->has_message_to_send) {
					// SEND TO CLIENT
					if (serv->send_servers_list) {
						LIST_FOREACH(innerServ, &servHead, entries) {
							if (innerServ->sock != serv->sock && innerServ->has_topic) {
								printf("Sending server %s to client\n", innerServ->topic);
								/* innerServ is a registered chat room */
								memset(messageToSend, 0, MAX); // clear the buffer
								snprintf(messageToSend, MAX, "%s %hu %s", inet_ntoa(serv_addr.sin_addr), innerServ->port, innerServ->topic);
								SSL_write(serv->ssl, messageToSend, MAX);
							}
						}
						serv->has_message_to_send = 0;
						serv->send_servers_list = 0;
					// SEND TO SERVER
					} else {
						if ( (n = SSL_write(serv->ssl, serv->toptr, MAX)) < 0) {
							if (errno != EWOULDBLOCK) {
								perror("write error on socket");
								servToRemove = serv;
								break;
							}
						/* a valid message was sent */
						} else {
							serv->toptr += n;
							if (serv->toptr >= &(serv->to[MAX])) {
								// Reset the to buffer after writing it all.
								serv->toptr = serv->to;
								serv->has_message_to_send = 0;
							}
						}
					}
				}
			}
			/* can't remove a list element in the LIST_FOREACH (Known bug) */
			if (servToRemove != NULL) {
				SSL_free(servToRemove->ssl);
				close(servToRemove->sock);
				/* Remove the server from the list */
				LIST_REMOVE(servToRemove, entries);
				/* Free the memory for the server */
				free(servToRemove);
			}
		}
	}
	/* Cleanup */
	LIST_FOREACH(serv, &servHead, entries) {
		SSL_free(serv->ssl);
		close(serv->sock);
		free(serv);
	}
	free(innerServ);
	close(sockfd);
	return 0;
}
