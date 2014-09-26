
backstroke: backstroke.cpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DDEBUG -o backstroke ./backstroke.cpp
.PHONY : backstroke

backstroke_block: backstroke_block.cpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DDEBUG -o backstroke_block ./backstroke_block.cpp
.PHONY : backstroke_block

backstroke_block_poll: backstroke_block.cpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG -o backstroke_block_poll ./backstroke_block.cpp
.PHONY : backstroke_block_poll

backstroke_full: backstroke_full.cpp
	clang++ -std=c++11 -Wall -Wno-write-strings -Wno-unused-function -DPOLL -DDEBUG -o backstroke_full ./backstroke_full.cpp
.PHONY : backstroke_full

clean:
	rm -rf ./backstroke backstroke_block backstroke_block_poll backstroke_full
.PHONY : clean
