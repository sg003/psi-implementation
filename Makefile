CXX      = g++
CXXFLAGS = -std=c++17 -O2
LIBS     = -lgmpxx -lgmp -lssl -lcrypto
ifeq ($(OS),Windows_NT)
	LIBS += -lws2_32
else
	LIBS += -lpthread
endif

HEADERS = config.hpp net.hpp gm.hpp bloom_filter.hpp timing.hpp ca/ca.hpp crypto/signature.hpp

all: psi_server psi_client psi_ca_authority experiment generate_dataset test_gm test_client

psi_server: server/server.cpp server/protocols.cpp bloom_filter.cpp gm.cpp ca/ca.cpp crypto/signature.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(filter-out $(HEADERS),$^) $(LIBS) -o $@

psi_client: client/client.cpp client/protocols.cpp bloom_filter.cpp gm.cpp ca/ca.cpp crypto/signature.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(filter-out $(HEADERS),$^) $(LIBS) -o $@

psi_ca_authority: ca/ca_server.cpp ca/ca.cpp bloom_filter.cpp gm.cpp crypto/signature.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(filter-out $(HEADERS),$^) $(LIBS) -o $@

experiment: experiment.cpp client/protocols.cpp server/protocols.cpp bloom_filter.cpp gm.cpp ca/ca.cpp crypto/signature.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(filter-out $(HEADERS),$^) $(LIBS) -o $@

generate_dataset: generate_dataset.cpp config.hpp
	$(CXX) $(CXXFLAGS) generate_dataset.cpp -o $@

test_gm: test_gm.cpp gm.cpp config.hpp gm.hpp
	$(CXX) $(CXXFLAGS) test_gm.cpp gm.cpp $(LIBS) -o $@

test_client: test_client.cpp bloom_filter.cpp gm.cpp config.hpp bloom_filter.hpp gm.hpp
	$(CXX) $(CXXFLAGS) test_client.cpp bloom_filter.cpp gm.cpp $(LIBS) -o $@

clean:
	rm -f psi_server psi_client psi_ca_authority experiment test_gm test_client generate_dataset
