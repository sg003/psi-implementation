CXX      = g++
CXXFLAGS = -std=c++17 -O2
LIBS     = -lgmpxx -lgmp -lssl -lcrypto

all: server client generate_dataset test_gm test_client

server: server/server.cpp server/protocols.cpp bloom_filter.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

client: client/client.cpp client/protocols.cpp bloom_filter.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

generate_dataset: generate_dataset.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

test_gm: test_gm.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

test_client: test_client.cpp bloom_filter.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f server client test_gm test_client generate_dataset
