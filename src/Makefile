
all: separator tap getinfo
.PHONY : all

separator: qb-separator.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG ./qb-separator.cpp -o qb-separator -lpthread
.PHONY : separator

tap: qb-tap.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG ./qb-tap.cpp -o qb-tap -lpthread
.PHONY : tap


backstroke: backstroke.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DDEBUG -o backstroke ./backstroke.cpp
.PHONY : backstroke

backstroke_block: backstroke_block.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DDEBUG -o backstroke_block ./backstroke_block.cpp
.PHONY : backstroke_block

backstroke_block_poll: backstroke_block.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG -o backstroke_block_poll ./backstroke_block.cpp
.PHONY : backstroke_block_poll

backstroke_full: backstroke_full.cpp netmap.hpp common.hpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG -o backstroke_full ./backstroke_full.cpp
.PHONY : backstroke_full

getinfo: getinfo.c
	clang -Wall -o getinfo ./getinfo.c
.PHONY : getinfo

clean:
	rm -rf qb-separator qb-tap getinfo
.PHONY : clean
