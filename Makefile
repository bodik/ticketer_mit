CC = gcc
CFLAGS = -g
LIBS = -lkrb5 -lcom_err -lk5crypto -lkrb5support

all: clean ticketer_mit

ticketer_mit:
	$(CC) $(CFLAGS) ticketer_mit.c $(LIBS) -o ticketer_mit

clean:
	rm -f ticketer_mit

lint:
	./run-clang-format.py ticketer_mit.c

valgrind:
	KRB5CCNAME=test.ccache valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
	./ticketer_mit 9c008f673b0c34d28ff483587f77ddb76f35545fcc69a0ae709f16f20e8765ee client1
