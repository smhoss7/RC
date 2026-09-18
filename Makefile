CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
TARGET = user
SRCS = user.c
 
.PHONY: all clean
 
all: $(TARGET)
 
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)
 
clean:
	rm -f $(TARGET) *.o