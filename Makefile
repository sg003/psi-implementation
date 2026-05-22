CXX      = g++
CXXFLAGS = -std=c++17 -O2
LIBS     = -lgmpxx -lgmp -lssl -lcrypto
ifeq ($(OS),Windows_NT)
	LIBS += -lws2_32
else
	LIBS += -lpthread
endif

all: psi_server psi_client psi_ca_authority experiment generate_dataset test_gm test_client

psi_server: server/server.cpp server/protocols.cpp bloom_filter.cpp gm.cpp ca/ca.cpp crypto/signature.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

psi_client: client/client.cpp client/protocols.cpp bloom_filter.cpp gm.cpp ca/ca.cpp crypto/signature.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

psi_ca_authority: ca/ca_server.cpp ca/ca.cpp bloom_filter.cpp gm.cpp crypto/signature.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

experiment: experiment.cpp client/protocols.cpp server/protocols.cpp bloom_filter.cpp gm.cpp ca/ca.cpp crypto/signature.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

generate_dataset: generate_dataset.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

test_gm: test_gm.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

test_client: test_client.cpp bloom_filter.cpp gm.cpp
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f psi_server psi_client psi_ca_authority experiment test_gm test_client generate_dataset
