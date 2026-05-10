CXX      = g++
CXXFLAGS = -std=c++17 -O2
LIBS     = -lgmpxx -lgmp -lssl -lcrypto
ifeq ($(OS),Windows_NT)
	LIBS += -lws2_32
endif

all: psi_server psi_client generate_dataset test_gm test_client

psi_server: server/server.cpp bloom_filter.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

psi_client: client/client.cpp client/protocols.cpp bloom_filter.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

generate_dataset: generate_dataset.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

test_gm: test_gm.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

test_client: test_client.cpp bloom_filter.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f psi_server psi_client test_gm test_client generate_dataset
