# mTLS-VID
This prototype simulates a client-server mTLS communication based in the Lightweight-SVID workload identity document, being developed by HPE-USP-SPIRE project.  
In this work, both sides own a signed LSVID containing their ID, public key, LSVID issuer and expiration. The LSVID are used as base to generate a self-signed certificate, that can be used in mTLS connections.  
The objective is to bind the LSVID with the communication actors, allowing to verify if the receiving ID really correspond to the workload in the communication.

# Execution
- Run server side with `go run server.go`
- Run client side with `go run client.go`

The server will listen for requests. For each request received it validate the client certificate and LSVID, also verifying if the public key in both documents are the same.
If so, the server accept the connection and sends a custom message to client.
