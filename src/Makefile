
all: separator tap getinfo
.PHONY : all

separator: qb-separator.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG ./qb-separator.cpp -o qb-separator -lpthread
.PHONY : separator

tap: qb-tap.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG ./qb-tap.cpp -o qb-tap -lpthread
.PHONY : tap

getinfo: getinfo.c
	clang -Wall -o getinfo ./getinfo.c
.PHONY : getinfo

backstroke:
	make -C ref backstroke
.PHONY : backstroke

backstroke_block:
	make -C ref backstroke_block
.PHONY : backstroke_block

backstroke_block_poll:
	make -C ref backstroke_block_poll
.PHONY : backstroke_block_poll

backstroke_full:
	make -C ref backstroke_full
.PHONY : backstroke_full

clean:
	rm -rf qb-separator qb-tap getinfo
.PHONY : clean
