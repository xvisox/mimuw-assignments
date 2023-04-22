COMPILER = g++
PRE_FLAGS = -std=c++20 -Wall -Werror
POST_FLAGS = -lpthread -lboost_program_options

all: sikradio-sender sikradio-receiver

sikradio-sender: sikradio-sender.cpp
	$(COMPILER) $(PRE_FLAGS) $< $(POST_FLAGS) -o $@

sikradio-receiver: sikradio-receiver.cpp
	$(COMPILER) $(PRE_FLAGS) $< $(POST_FLAGS) -o $@

.PHONY: clean

clean:
	rm -f sikradio-sender sikradio-receiver *.o

-include $(DEPS)