
all: separator tap getinfo
.PHONY : all

separator: qb.cpp netmap.hpp common.hpp
	c++ -I../netmap/sys -std=c++11 -Wall -Wno-write-strings -Wno-unused-variable -Wno-unused-function -DPOLL -DDEBUG ./qb.cpp -o qb-separator -lpthread
.PHONY : separator

tap: qb.cpp netmap.hpp common.hpp ether.hpp
	c++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DFULLTAP -DPOLL -DDEBUG ./qb.cpp -o qb-tap -lpthread
.PHONY : separator

getinfo: getinfo.c
	cc -Wall -o getinfo ./getinfo.c -I ../../netmap/sys/
.PHONY : getinfo

clean:
	rm -rf qb-separator qb-tap getinfo
.PHONY : clean
