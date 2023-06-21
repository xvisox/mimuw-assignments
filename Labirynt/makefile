CC       = gcc
CFLAGS   = -Wall -Wextra -Wno-implicit-fallthrough -std=c17 -O2

.PHONY: all clean

all: labyrinth

labyrinth: main.o labyrinth_reader.o labyrinth_utility.o labyrinth_solver.o queue.o
	$(CC) $^ -o labyrinth 

queue.o: queue.h error_handle.h
labyrinth_reader.o: labyrinth_reader.h error_handle.h
labyrinth_utility.o: labyrinth_utility.h bit_operations.h error_handle.h
labyrinth_solver.o: labyrinth_solver.h queue.h bit_operations.h error_handle.h
main.o: labyrinth_solver.h labyrinth_reader.h queue.h error_handle.h

clean:
	-rm -f *.o labyrinth