
OLX=$(HOME)/lib/libolx
PATCH=$(HOME)/lib/libpatch
CAPSTONE=/usr/include

libdw: 
	gcc -c -Wall -fPIC -g dw-log.c -o dw-log.o
	gcc -c -Wall -fPIC -g dw-protect-oid.c -o dw-protect-oid.o
	gcc -c -Wall -fPIC -g dw-protect-none.c -o dw-protect-none.o
	gcc -c -Wall -fPIC -g -I $(PATCH)/include -I $(CAPSTONE)/capstone dw-registers.c -o dw-registers.o
	gcc -c -Wall -fPIC -g -I $(PATCH)/include -I $(CAPSTONE)/capstone dw-disassembly.c -o dw-disassembly.o
	gcc -c -Wall -fPIC -g dw-wrap-glibc.c -o dw-wrap-glibc.o
	gcc -c -Wall -fPIC -g dw-printf.c -o dw-printf.o
	gcc -c -Wall -fPIC -g  -I $(PATCH)/include dw-preload.c -o dw-preload.o
	gcc -shared -g -o libmallocsan.so dw-log.o dw-protect-oid.o dw-disassembly.o dw-registers.o dw-wrap-glibc.o dw-printf.o dw-preload.o -lcapstone -L $(PATCH)/lib/ -lpatch -lunwind
	gcc -c -Wall -g simple.c -o simple.o
	#gcc -O2 -g -o simple simple.o
	gcc -g -o simple-dw simple.o dw-log.o dw-protect-oid.o dw-disassembly.o dw-registers.o dw-wrap-glibc.o dw-printf.o dw-preload.o -lcapstone -L $(PATCH)/lib -lpatch -l unwind	
        
clean:
	-rm *.o *.so simple simple-dw
