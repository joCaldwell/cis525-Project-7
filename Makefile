#
# Makefile for chat server
#
CC	= gcc
EXECUTABLES=chatClient2 chatServer2 directoryServer2
INCLUDES	= $(wildcard *.h)
SOURCES	= $(wildcard *.c)
DEPS		= $(INCLUDES)
OBJECTS	= $(SOURCES:.c=.o)
OBJECTS	+= $(SOURCES:.c=.dSYM*)
EXTRAS	= $(SOURCES:.c=.exe*)
LIBS		=
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
# CFLAGS += -Wc99-c11-compat -Wmaybe-uninitialized \
					-Wformat-truncation=2 -Wstringop-truncation \
					-Wformat-overflow=2 -Wformat-signedness

all:	chat2

chat2:	$(EXECUTABLES)


chatClient2: chatClient2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

chatServer2: chatServer2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<

directoryServer2: directoryServer2.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(LIBS) -o $@ $<


# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES) $(EXTRAS)
