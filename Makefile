CC = gcc
CFLAGS = -g
#LDFLAGS = 
LIBS = -lkrb5 -lcom_err -lk5crypto -lkrb5support

all: clean ticketer_mit

ticketer_mit:
	$(CC) $(CFLAGS) ticketer_mit.c $(LIBS) -o ticketer_mit

clean:
	rm -f ticketer_mit

lint:
	./run-clang-format.py ticketer_mit.c

valgrind:
	valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
	./ticketer_mit
