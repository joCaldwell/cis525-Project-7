#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <stdlib.h>
#include <unistd.h>
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include "openssl/err.h"
#include "inet.h"
#include "common.h"

#define FOOTBALL_SERVER_CERT "certs/football-server-cert.crt"
#define FOOTBALL_SERVER_KEY "certs/football-server-key.pem"

#define SOCCER_SERVER_CERT "certs/soccer-server-cert.crt"
#define SOCCER_SERVER_KEY "certs/soccer-server-key.pem"

struct client {
	char 				name[MAX], to[MAX], fr[MAX];
	char				*toptr, *frptr;
	int 				has_name, sock, has_message_to_send;
	SSL					*ssl;
	LIST_ENTRY(client) 	entries;
};

void load_certificates(SSL_CTX *ctx, char *cert_file, char *key_file) {
    // Load the server's certificate
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		perror("Error loading server certificate");
		exit(EXIT_FAILURE);
	}

    // Load the server's private key
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		perror("Error loading server private key");
		exit(EXIT_FAILURE);
	}

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
	char							command, s[MAX], topic[MAX], message[MAX], messageToSend[MAX];
	int								sockfd, newsockfd, n, j;
	uint16_t						port;
	unsigned int					clilen;
	LIST_HEAD(client_list, client) 	clientHead;
	fd_set 							readset, writeset;
	struct sockaddr_in				cli_addr, serv_addr, dir_serv_addr;
	struct client 					*cli, *innerCli, *cliToRemove;

	char							expected_cn[MAX], server_cn[MAX];
	X509_NAME						*subject_name;
	X509							*cert;
	SSL_CTX 						*ctx;
	SSL 							*dir_ssl; 
	BIO 							*bio;
	SSL_METHOD 						*method;


	/* check number of command line arguments */
	if (argc < 3) {
		perror("server: not enough arguments supplied.\nRun with: `chatserver2 \"<topic>\" <port>`");
		exit(1);
	}

	/* assign port number and topic */
	memset(topic, 0, MAX); // clear the buffer
	snprintf(topic, MAX, "%s", argv[1]);
	if ((j = sscanf(argv[2], "%hu", &port)) != 1) {
		perror("server: port read was unsucessfull (Be sure the second argument is a valid port number)");
		exit(1);
	}
	/* check topic name (must be soccer or football) */
	if (strncmp(topic, "soccer", MAX) != 0 && strncmp(topic, "football", MAX) != 0) {
		perror("server: topic must be either soccer or football");
		exit(1);
	}

	/* Initialze the list of clients */
	LIST_INIT(&clientHead);

	/* SSL Initialization */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	method = TLS_client_method();
	ctx = SSL_CTX_new(method);

	if (!ctx) {
		fprintf(stderr, "Error creating SSL context\n");
		exit(1);
	}

	// Load CA certificate to verify the server's certificate
	if (SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) <= 0) {
		fprintf(stderr, "Error loading CA certificate: 1\n");
		SSL_CTX_free(ctx);
		exit(1);
	}

	/* Set up the address of the directory server to be contacted. */
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family			= AF_INET;
	dir_serv_addr.sin_addr.s_addr		= inet_addr(SERV_HOST_ADDR);
	dir_serv_addr.sin_port				= htons(SERV_TCP_PORT);

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}
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

	/* Set socket to non blocking */
	int val = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, val | O_NONBLOCK);

	// Create an SSL object and bind it to the socket
    dir_ssl = SSL_new(ctx);
    SSL_set_fd(dir_ssl, sockfd);

    // Initiate the handshake
	int result;
    while ((result = SSL_connect(dir_ssl)) <= 0) {
        int err = SSL_get_error(dir_ssl, result);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			continue;
        } else {
            ERR_print_errors_fp(stderr);
			printf("SSL handshake failed\n");
			exit(1);
        }
    }
	printf("SSL handshake successful\n");

		/* Retreive cert from server */
	cert = SSL_get_peer_certificate(dir_ssl);

    if (cert <= 0) {
        fprintf(stderr, "No server certificate received\n");
        exit(1);
    }

	subject_name = X509_get_subject_name(cert);
    if (subject_name <= 0) {
        fprintf(stderr, "Failed to get subject name from certificate\n");
 
        exit(1);
    }
	
    if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, server_cn, sizeof(server_cn)) <= 0) {
        fprintf(stderr, "Error retrieving common name from cert\n");
        exit(1);
    }

	snprintf(expected_cn, MAX, "%s", "Directory Server");

	/* On connection check sever cn against expected cn */
    if (strcmp(server_cn, expected_cn) != 0) {
        fprintf(stderr, "Common Name mismatch: expected '%s', got '%s'\n", expected_cn, server_cn);
        exit(1);
    }
	fprintf(stdout, "Name verified! \n");

	/* Send port number and topic to the directory server to register it */
	memset(messageToSend, 0, MAX); // clear the buffer
	snprintf(messageToSend, MAX, "s %hu %s", port, topic);

	for (;;) {
		printf("Connected to directory server\n");
		FD_ZERO(&readset); FD_ZERO(&writeset);
		FD_SET(sockfd, &writeset);
		if (n = select(sockfd+1, NULL, &writeset, NULL, NULL) > 0) {
			if ( (n = SSL_write(dir_ssl, messageToSend, MAX)) < 0) {
				if (errno != EWOULDBLOCK) {
					perror("read error on socket");
					cliToRemove = cli;
					break;
				}
			} else {
				// We have written something, break the loop
				break;
			}
			// write(sockfd, messageToSend, MAX);
		}
	}

	// Get verification from directory that registering was successfull
	memset(s, 0, MAX); // clear the buffer
	for (;;) {
		FD_ZERO(&readset); FD_ZERO(&writeset);
		FD_SET(sockfd, &readset);
		select(sockfd+1, &readset, NULL, NULL, NULL);
		if ( (n = SSL_read(dir_ssl, s, MAX)) < 0) {
			if (errno != EWOULDBLOCK) {
				perror("read error from dirctory");
				exit(1);
			}
		} else {
			// We have read something, Verify the message after.
			break;
		}
	}

	memset(message, 0, MAX); // clear the buffer
	// Check message from Directory server (first char 's': success, 'f': fail)
	j = sscanf(s, "%c %[^\n]", &command, message);
	if (j <= 0) {
		perror("Failed to read verification from server: 2");
		exit(1);

	} else if (j == 1) {
		// Only one character was sent, if it was 's' then verification was successful
		if (command != 's') {
			perror("Failed to read verification from server: 3");
			exit(1);
		}

	} else if (j == 2) {
		// Both arguments were supplied, check the values
		if (command == 'f') {
			// Verifiaction failed print error message from directory
			exit(1);
		} else if (command != 's') {
			perror("Failed to read verification from server: 4");
			exit(1);
		}
	}

	/* RESET TO LISTEN FOR CLIENTS */
	SSL_free(dir_ssl);
	SSL_CTX_free(ctx);
	// method = TLS_server_method();
	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Soccer server
	if (strncmp(topic, "soccer", MAX) == 0) {
		load_certificates(ctx, SOCCER_SERVER_CERT, SOCCER_SERVER_KEY);
	}

	// Football server
	if (strncmp(topic, "football", MAX) == 0) {
		load_certificates(ctx, FOOTBALL_SERVER_CERT, FOOTBALL_SERVER_KEY);
	}

	// Load CA certificate to verify the server's certificate
	if (SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) <= 0) {
		fprintf(stderr, "Error loading CA certificate: 1\n");
		SSL_CTX_free(ctx);
		exit(1);
	}


	// SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}
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
					/* Set socket to non blocking */
					int val = fcntl(newsockfd, F_GETFL, 0);
					fcntl(newsockfd, F_SETFL, val | O_NONBLOCK);

					/* create new server */
					struct client *newCli = malloc(sizeof(struct client));

					newCli->ssl = SSL_new(ctx);
					SSL_set_fd(newCli->ssl, newsockfd);

					/* SSL handshake with the server/client */
					int handshake_result, err;
					while ( (handshake_result = SSL_accept(newCli->ssl)) <= 0) {
						err = SSL_get_error(newCli->ssl, handshake_result);
						if ((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE)) {
							ERR_print_errors_fp(stderr);
							SSL_free(newCli->ssl);
							close(newsockfd);
							printf("Handshake failed\n");
						}
					}
					printf("Handshake successful\n");

					/* initialize server variables */
					//struct client *newCli = malloc(sizeof(struct client));
					memset(newCli->name, '\0', MAX);
					newCli->has_name = 0;
					newCli->sock = newsockfd;
					newCli->toptr = newCli->to;
					newCli->frptr = newCli->fr;
					LIST_INSERT_HEAD(&clientHead, newCli, entries);
					printf("Client Connected\n");
				}

			}

			/* Reading messages*/
			cliToRemove = NULL;
			LIST_FOREACH(cli, &clientHead, entries) {
				if (FD_ISSET(cli->sock, &readset)) {
					/* Read the message */
					if ( (n = SSL_read(cli->ssl, cli->frptr, &(cli->fr[MAX]) - cli->frptr)) < 0) {
						if (errno != EWOULDBLOCK) {
							perror("read error on socket");
							cliToRemove = cli;
							break;
						}
					} else if (0 == n) {
						fprintf(stderr, "%s:%d: EOF on socket\n", __FILE__, __LINE__);
						if (cli->has_name) {
							snprintf(messageToSend, MAX, "%s has left the chat\n", cli->name);

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
							snprintf(messageToSend, MAX, "Bad format\n");
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
									printf("First user joined: %s\n", message);

								} else {
									if (cli->has_name) {
										snprintf(messageToSend, MAX, "%s has changed name to %s\n", cli->name, message);
									} else {
										snprintf(messageToSend, MAX, "%s has joined the chat\n", message);
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
					printf("sending %s to client\n", cli->to);
					if ( (n = SSL_write(cli->ssl, cli->toptr, MAX)) < 0) {
						if (errno != EWOULDBLOCK) {
							perror("read error on socket");
							cliToRemove = cli;
							break;
						}
					/* valid message was sent */
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
				SSL_free(cliToRemove->ssl);
				close(cliToRemove->sock);
				/* Remove the client from the list */
				LIST_REMOVE(cliToRemove, entries);
				free(cliToRemove);
			}
		}
	}

	/* Cleanup */
	LIST_FOREACH(cli, &clientHead, entries) {
		SSL_free(cli->ssl);
		close(cli->sock);
		free(cli);
	}
	free(innerCli);
	close(sockfd);
	return 0;
}