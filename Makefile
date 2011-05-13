CC = gcc
CCFLAGS = -Wall -pthread -ggdb
CFLAGS = -Wall -O2 -pthread -ggdb -I. 
LIBS = -lpcap
OBJS = parse.o sniff.o main.o log.o
SRCS = ${OBJS:.o=.c}
TARGET = siphon

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CCFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) *~ *.core core siphon
