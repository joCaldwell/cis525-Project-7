#
# Makefile for chat server
#
CC	= gcc
EXECUTABLES=chatClient5 chatServer5 directoryServer5
INCLUDES	= $(wildcard *.h)
SOURCES	= $(wildcard *.c)
DEPS		= $(INCLUDES)
OBJECTS	= $(SOURCES:.c=.o)
OBJECTS	+= $(SOURCES:.c=.dSYM*)
EXTRAS	= $(SOURCES:.c=.exe*)
LIBS	= -lssl -lcrypto
LDFLAGS	=
CFLAGS	= -g -ggdb -std=c99 -Wmain \
				-Wignored-qualifiers -Wshift-negative-value \
				-Wuninitialized -Wunused -Wunused-macros \
				-Wunused-function -Wunused-parameter -Wunused-but-set-parameter \
				-Wreturn-type \
				-Winit-self -Wimplicit-int -Wimplicit-fallthrough -Wparentheses \
				-Wformat=2 -Wformat-nonliteral -Wformat-security -Wformat-y2k \
				-Wuninitialized -Wswitch-default -Wfatal-errors
CFLAGS	+= -ggdb3
CFLAGS	+= -Wformat-security -Wconversion -Wformat-overflow=2 -Wformat-signedness
CFLAGS += -Wc99-c11-compat -Wmaybe-uninitialized \
					-Wformat-truncation=2 -Wstringop-truncation \
					-Wformat-overflow=2 -Wformat-signedness

all:	chat2

chat2:	$(EXECUTABLES)


chatClient5: chatClient5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< -lssl -lcrypto

chatServer5: chatServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< -lssl -lcrypto

directoryServer5: directoryServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $< -lssl -lcrypto


# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES) $(EXTRAS)
