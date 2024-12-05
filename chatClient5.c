#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include "openssl/err.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"

// install : sudo apt-get install libssl-dev

struct server{
	char 				topic[MAX], ip[20];
	uint16_t 			port;
	LIST_ENTRY(server) 	entries;
	int 				index;
	SSL					*ssl;
};

int main()
{
	char 				s[MAX] = {'\0'};
	fd_set				readset;
	int					sockfd, i, j, k, selected_serv, result;
	ssize_t				nread;
	struct sockaddr_in 	serv_addr, dir_serv_addr;
	struct timeval 		timeout;
	char				topic[MAX], ip[20], expected_cn[MAX], server_cn[MAX];
	uint16_t			port;
	LIST_HEAD(server_list, server) servHead;
	struct server 		*serv, *innerServ;
	X509_NAME			*subject_name;
	X509				* cert;
	SSL_CTX 			*ctx;
	SSL 				*dir_ssl, *serv_ssl;
	const SSL_METHOD 	*method;


	LIST_INIT(&servHead);

	
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

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		exit(1);
	}

	/* Connect to the dirctory server to get a list of chat rooms. */
	if (connect(sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("client: can't connect to directory server");
		exit(1);
	} 

	// Create an SSL object and bind it to the socket
    dir_ssl = SSL_new(ctx);
    SSL_set_fd(dir_ssl, sockfd);

    // Initiate the handshake
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

	/* Free certificate */
	X509_free(cert);

	/* tell the directory server we are a client */
	snprintf(s, MAX, "c");
	SSL_write(dir_ssl, s, MAX);

	/* set timeout of chatroom select to 1 second */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	/* Select for directory server */
	j = 1;
	for(;;) {
		memset(s, 0, MAX); // clear the buffer
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);

		if ( (k = select(sockfd+1, &readset, NULL, NULL, &timeout)) > 0) {
			if (SSL_read(dir_ssl, s, MAX) == -1) {
				perror("Something went wrong\n");
				exit(1);
			}

			if ( (i = sscanf(s, "%s %hu %[^\n]", ip, &port, topic)) != 3) {
				/* Failed reading -> we have received all servers from the directory */
				break;
			} else {
				struct server *newServ = malloc(sizeof(struct server));
				newServ->port = port;
				snprintf(newServ->ip, 20, "%s", ip);
				snprintf(newServ->topic, MAX, "%s", topic);
				newServ->index = j;
				LIST_INSERT_HEAD(&servHead, newServ, entries);
				j++;
			}
		} else if (k == 0) {
			/* The select timed out */
			break;
		}
	}
	close(sockfd);

	printf("Welcome to the Chat Client!\n");
	printf("I Will give you a list of servers to connect to, type in the number of the server you want to join.\n");
	LIST_FOREACH(serv, &servHead, entries) {
		printf("%d: %s\n", serv->index, serv->topic);
	}
	if (LIST_EMPTY(&servHead)) {
		printf("There are no chat servers right now check back later ;(\n");
		exit(1);
	}
	for (;;) {
		printf("Enter a number above\n");
		if ((i = scanf("%d", &selected_serv)) == 1) {
			if (selected_serv > 0 && selected_serv < j) {
				/* Valid server */
				break;
			}
		} else {
            // Clear the input buffer if scanf fails
            printf("Invalid input. Please enter a valid number.\n");
            scanf("%*[^\n]");  // Discard invalid input
        }
	}

	LIST_FOREACH(innerServ, &servHead, entries) {
		if (innerServ->index == selected_serv) {
			serv = innerServ;
			break;
		}	
	}

	/* Set up the address of the directory server to be contacted. */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family			= AF_INET;
	serv_addr.sin_addr.s_addr		= inet_addr(serv->ip);
	serv_addr.sin_port				= htons(serv->port);


	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		exit(1);
	}

	/* Connect to the server of choice. */
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("client: can't connect to server");
		exit(1);
	} 


	// Create an SSL object and bind it to the socket
	SSL_free(dir_ssl);
	SSL_CTX_free(ctx);
	ctx = SSL_CTX_new(method);

	// Load CA certificate to verify the server's certificate
	if (SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) <= 0) {
		fprintf(stderr, "Error loading CA certificate: 1\n");
		SSL_CTX_free(ctx);
		exit(1);
	}

	serv_ssl = SSL_new(ctx);
	SSL_set_fd(serv_ssl, sockfd);

	// Initiate the handshake
	result = SSL_connect(serv_ssl);
	if (result <= 0) {
		ERR_print_errors_fp(stderr);
		printf("SSL handshake failed\n");
		close(sockfd);
		SSL_free(serv_ssl);
		SSL_CTX_free(ctx);
		exit(1);
	}
	printf("SSL handshake successful\n");

	/* Retreive cert from server */
	cert = SSL_get_peer_certificate(serv_ssl);

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

	if (strncmp(serv->topic , "soccer", MAX) == 0) {
		snprintf(expected_cn, MAX, "%s", "Soccer Server");
	}
	else if (strncmp(serv->topic , "football", MAX) == 0) {
		snprintf(expected_cn, MAX, "%s", "Fooball Server");
	}
	else {
		fprintf(stderr, "Unknown server topic\n");
		exit(1);
	}

	/* On connection check sever cn against expected cn */
    if (strcmp(server_cn, expected_cn) != 0) {
        fprintf(stderr, "Common Name mismatch: expected '%s', got '%s'\n", expected_cn, server_cn);
        exit(1);
    }
	printf("Listed below are some available commands ...\n");
	printf("\t`n <name>` - set or change your name\n");
	printf("\t`s <message>` - Send a message to the preople in the chat room\n");

	for(;;) {
		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);
		if (select(sockfd+1, &readset, NULL, NULL, NULL) > 0)
		{
			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				memset(s, 0, MAX); // clear the buffer
				if ((nread = read(STDIN_FILENO, s, MAX)) > 0) {
					size_t len = strlen(s);
					/* replace the new line character at the end of the string with the terminator character. */
					if (s[len-1] == '\n') {
						s[len-1] = '\n'; // Jank but I couldn't find another way
						s[len] = '\0';
					}
					/* Send the user's message to the server */
					SSL_write(serv_ssl, s, MAX);
				} else {
					printf("Error reading or parsing user input\n");
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
				memset(s, 0, MAX); // clear the buffer
				if ((nread = SSL_read(serv_ssl, s, MAX)) <= 0) {
					printf("Error reading from server\n");
					close(sockfd);
					break;
				} else {
					printf("%s\n", s);
				}
			}
		}
	}
	close(sockfd);
}
