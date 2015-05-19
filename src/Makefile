
all: separator tap
.PHONY : all

debug: separator_debug tap_debug
.PHONY : debug

INCLUDE:="-I../../netmap/sys"

#define_option TAPSW, DROPLLC POLL DEBUG

separator: qb.cpp netmap.hpp common.hpp
	c++ ${INCLUDE} -O3 -std=c++11 -Wall -Wno-write-strings -Wno-unused-variable -Wno-unused-function -DPOLL -DDROPLLC -DTAPSW ./qb.cpp -o qb-separator -lpthread
.PHONY : separator

tap: qb.cpp netmap.hpp common.hpp ether.hpp
	c++ ${INCLUDE} -O3 -std=c++11 -Wall -Wno-write-strings -Wno-unused-variable -Wno-unused-function -DFULLTAP -DPOLL -DDROPLLC -DTAPSW ./qb.cpp -o qb-tap -lpthread
.PHONY : tap

separator_debug: qb.cpp netmap.hpp common.hpp
	c++ ${INCLUDE} -g -std=c++11 -Wall -Wno-write-strings -Wno-unused-variable -Wno-unused-function -DDEBUG -DPOLL -DDROPLLC -DTAPSW ./qb.cpp -o qb-separator_debug -lpthread
.PHONY : separator

tap_debug: qb.cpp netmap.hpp common.hpp ether.hpp
	c++ ${INCLUDE} -g -std=c++11 -Wall -Wno-write-strings -Wno-unused-variable -Wno-unused-function -DDEBUG -DFULLTAP -DPOLL -DDROPLLC -DTAPSW ./qb.cpp -o qb-tap_debug -lpthread
.PHONY : tap

getinfo: getinfo.c
	cc -Wall ${INCLUDE} -g -o getinfo ./getinfo.c -I ../../netmap/sys/
.PHONY : getinfo

clean:
	rm -rf qb-separator qb-tap getinfo qb-separator_debug qb-tap_debug
.PHONY : clean
