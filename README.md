# TLSonSGX

TLSonSGX is a wrapper for crypto libraries executing in SGX enclaves. It was initialy designed for Open vSwitch, to allow replacing the default OpenSSL library with a crypto library running inside an SGX enclave. This approach allows to both protect the authentication credentials and the cryptgraphic context during TLS session negotiation. 


