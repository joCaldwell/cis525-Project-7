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
};

int main()
{
	char 				s[MAX] = {'\0'};
	fd_set				readset;
	int					sockfd, i, j, k, selected_serv;
	ssize_t				nread;
	struct sockaddr_in 	serv_addr, dir_serv_addr;
	struct timeval 		timeout;
	char				topic[MAX], ip[20], expected_cn[MAX], server_cn[MAX];
	uint16_t			port;
	LIST_HEAD(server_list, server) servHead;
	struct server 		*serv, *innerServ;
	X509_NAME			*subject_name;
	X509				* cert;


	LIST_INIT(&servHead);

	/* openssl stuff */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

	const char *ca_cert_file = "certs/ca-cert.pem";
	const SSL_METHOD *method = TLS_client_method();
	ctx = SSL_CTX_new(method);


	if (!ctx) {
		fprintf(stderr, "Error creating SSL context\n");
		exit(1);
	}


	// Prepare folder formatting loading certs */
	/* Use this at the command line */
	/* c_rehash "/../certs" */


	// Load CA certificate to verify the server's certificate
	if (SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL) <= 0) {
		fprintf(stderr, "Error loading CA certificate: 1\n");
		SSL_CTX_free(ctx);
		exit(1);
	}

	/* Do this to connect to server / direcotry */
	// // Create a new SSL object
	ssl = SSL_new(ctx);
	if (ssl <= 0) {
        fprintf(stderr, "BIO NULL\n");
		SSL_CTX_free(ctx);
		exit(1);
    }


	/* Creating an opening a connection */
	bio = BIO_new_connect("127.0.0.1:4433"); 
	if(bio == NULL)
	{
		fprintf(stderr, "Error creating bio object\n");
		SSL_free(ssl);
        SSL_CTX_free(ctx);
		BIO_free_all(bio);
		exit(1); 
	}
	
	/* ssl, rbio, wbio */
	SSL_set_bio(ssl, bio, bio);

	//BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);


	/* Reading from the connection 
	int x = BIO_read(bio, buf, len);
	if(x == 0)
	{
		// Handle closed connection /
	}
	else if(x < 0)
	{
	   if(! BIO_should_retry(bio))
		{
			// Handle failed read here /
		}

		/ Do something to handle the retry /
	}


	 Writing to the connection 
	if(BIO_write(bio, buf, len) <= 0)
	{
		if(! BIO_should_retry(bio))
		{
			/ Handle failed write here /
		}

		/ Do something to handle the retry 
	}*/


	/* Connecting to server */
	if(BIO_do_connect(bio) <= 0)
	{
		if(BIO_should_retry(bio) <= 0){
			fprintf(stderr, "Error establishing connection");
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			BIO_free_all(bio);
			exit(1);
		}
	}


	if(SSL_get_verify_result(ssl) != X509_V_OK)
	{
		fprintf(stderr, "Error verifying the CA");
		exit(1);
	}


	/* Retreive cert from server */
	cert = SSL_get_peer_certificate(ssl);

    if (cert <= 0) {
        fprintf(stderr, "No server certificate received\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
		BIO_free_all(bio);
        exit(1);
    }


	subject_name = X509_get_subject_name(cert);
    if (subject_name <= 0) {
        fprintf(stderr, "Failed to get subject name from certificate\n");
        X509_free(cert);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(1);
    }
	
    if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, server_cn, sizeof(server_cn)) <= 0) {
        fprintf(stderr, "Error retrieving common name from cert\n");
        X509_free(cert);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(1);
    }

	// BIO_free_all()

	/* Cleanup SSL */
	//SSL_CTX_free(ctx);


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

		// IMPLEMENT ME : still need retreive server info from server prior to acceptign the connection 
	/* On connection check sever cn against expected cn */
    if (strcmp(server_cn, expected_cn) != 0) {
        fprintf(stderr, "Common Name mismatch: expected '%s', got '%s'\n", expected_cn, server_cn);
        X509_free(cert);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(1);
    }

	/* Connect to the dirctory server to get a list of chat rooms. */
	if (connect(sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("client: can't connect to directory server");
		exit(1);
	} 


	/* Free certificate */
	X509_free(cert);


	/* tell the directory server we are a client */
	snprintf(s, MAX, "c");
	write(sockfd, s, MAX);

	/* Select for directory server */
	j = 1;

	/* set timeout of chatroom select to 1 second */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	for(;;) {

		memset(s, 0, MAX); // clear the buffer
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);

		if ( (k = select(sockfd+1, &readset, NULL, NULL, &timeout)) > 0) {
			if (read(sockfd, s, MAX) == -1) {
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
						s[len-1] = '\0'; // Jank but I couldn't find another way
					}
					/* Send the user's message to the server */
					write(sockfd, s, MAX);
				} else {
					printf("Error reading or parsing user input\n");
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
				memset(s, 0, MAX); // clear the buffer
				if ((nread = read(sockfd, s, MAX)) <= 0) {
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
