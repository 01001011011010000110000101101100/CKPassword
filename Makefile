CC = gcc
CFLAGS = -Wall -Wextra -O0 -D_POSIX_C_SOURCE=200112L -Isqlite
LIBS = -lsodium -lrt -lm

TARGET = CKPassword
SRCS = passwords_manager.c encryption.c database_handler.c menu.c sqlite/sqlite3.c io.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)