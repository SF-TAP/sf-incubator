
all: separator tap getinfo
.PHONY : all

INCLUDE:="-I../../netmap/sys"

separator: qb.cpp netmap.hpp common.hpp
	c++ ${INCLUDE} -O3 -std=c++11 -Wall -Wno-write-strings -Wno-unused-variable -Wno-unused-function -DSTP -DDEBUG -DPOLL ./qb.cpp -o qb-separator -lpthread
.PHONY : separator

tap: qb.cpp netmap.hpp common.hpp ether.hpp
	c++ ${INCLUDE} -O3 -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DFULLTAP -DPOLL -DSTP -DDEBUG ./qb.cpp -o qb-tap -lpthread
.PHONY : separator

getinfo: getinfo.c
	cc -Wall ${INCLUDE} -g -o getinfo ./getinfo.c -I ../../netmap/sys/
.PHONY : getinfo

clean:
	rm -rf qb-separator qb-tap getinfo
.PHONY : clean
