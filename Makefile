CC = gcc
CFLAGS = -Wall -Wextra -O3 -D_POSIX_C_SOURCE=200112L
LIBS = -lsodium -lrt -lm

TARGET = password_manager
SRCS = password_manager.c encryption.c database_handler.c menu.c sqlite3.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)