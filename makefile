unppath=../../unpv13e/libunp.a
all:main ifindex
.PHONY:all
ifindex:cppfiles/ifindex.c
	gcc -o ifindex cppfiles/ifindex.c
main: main.o mcchat.o
	g++ -o main main.o mcchat.o $(unppath) -lpthread -lcrypto
main.o:cppfiles/main.cpp headfiles/mcchat.h
	g++ -c  cppfiles/main.cpp
mcchat.o:cppfiles/mcchat.cpp headfiles/mcchat.h
	g++ -c  cppfiles/mcchat.cpp
.PHONY: clean
clean:
	-rm ifindex main main.o mcchat.o
