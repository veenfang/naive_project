test : test.c sniffer.o radiotap-parser.o
	gcc -o test test.c sniffer.o radiotap-parser.o -lpcap -lpthread
sniffer.o : sniffer.c sniffer.h
	gcc -c sniffer.c
radiotap-parser.o : radiotap-parser.c radiotap-parser.h
	gcc -c radiotap-parser.c
