CXX ?= g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Iinclude -I../c/include

all: ../../bin/atp-cpp

../../bin/atp-cpp: src/advancetether.cpp src/cli.cpp ../c/src/advancetether.c include/advancetether.hpp
	mkdir -p ../../bin
	$(CXX) $(CXXFLAGS) src/advancetether.cpp src/cli.cpp ../c/src/advancetether.c -o ../../bin/atp-cpp

test: ../../bin/atp-cpp
	../../bin/atp-cpp --self-test

clean:
	rm -f ../../bin/atp-cpp
