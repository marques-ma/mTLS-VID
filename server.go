package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
	"crypto/sha256"
)

// LSVID structure representing the LSVID identity
type LSVID struct {
	Version              string
	IssuerID             string
	SubjectID            string
	SubjectPublicKey     crypto.PublicKey
	SubjectKeyExpiration time.Time
	Signature            []byte
}

// ServeHTTP handles incoming HTTP requests
func ServeHTTP(w http.ResponseWriter, r *http.Request) {

	client := r.TLS.PeerCertificates[0]
	log.Println("Received request from client: ", client.Subject.CommonName)

	// Extract the raw client certificate
	rawCert := r.TLS.PeerCertificates[0].Raw

	// Verify client certificate and LSVID
	if err := VerifyPeerCertificate([][]byte{rawCert}, r.TLS.VerifiedChains); err != nil {
		log.Println("Invalid client certificate:", err)
		http.Error(w, "Invalid client certificate", http.StatusUnauthorized)
		return
	}
	// Verify LSVID of the client
	if !verifyLSVID(r.Header.Get("LSVID")) {
		log.Println("Invalid client LSVID")
		http.Error(w, "Invalid client LSVID", http.StatusUnauthorized)
		return
	}

	log.Println("Valid client LSVID")

	ramdomLimit := new(big.Int).Lsh(big.NewInt(1), 64)
	randomHi, err := rand.Int(rand.Reader, ramdomLimit)
	if err != nil {
		log.Printf("Failed to generate random number: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Send a message from the server to the client
	message := "Hello number " + randomHi.String() + " to client " + client.Subject.CommonName
	_, err = w.Write([]byte(message))
	if err != nil {
		log.Printf("Failed to send message to client: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("Message sent to client: %s \n", message)
}

// ListenAndServeLSVID listens on the specified address and handles incoming LSVID-based mTLS requests
func ListenAndServeLSVID(addr string, handler http.Handler, serverLSVID LSVID, privateKey crypto.PrivateKey) error {
	// Generate a self-signed X.509 certificate based on the LSVID data
	certBytes, err := GenerateCertificate(serverLSVID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	// Create a new TLS certificate using the generated certificate bytes and private key
	cert, err := tls.X509KeyPair(certBytes, certBytes)
	if err != nil {
		return fmt.Errorf("failed to create TLS certificate: %v", err)
	}

	// Create a new TLS configuration for the server
	serverTLSConfig := &tls.Config{
		ClientAuth:				tls.RequireAnyClientCert,
		ClientCAs:				nil,
		Certificates:			[]tls.Certificate{cert},
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", addr, serverTLSConfig)
	if err != nil {
		return fmt.Errorf("failed to create TLS listener: %v", err)
	}

	// Create HTTP server
	server := &http.Server{
		Handler:   handler,
		TLSConfig: serverTLSConfig,
	}

	log.Printf("Listening for LSVID-based mTLS connections on %s", addr)

	// Start the server
	err = server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start LSVID-based mTLS server: %v", err)
	}

	return nil
}

// Helper function to verify LSVID
func verifyLSVID(lsvid string) bool {
	// TODO: Implement LSVID verification logic
	// ...

	// Placeholder LSVID verification
	return true
}

// GenerateCertificate generates a self-signed X.509 certificate based on the LSVID data
func GenerateCertificate(lsvid LSVID, privateKey crypto.PrivateKey) ([]byte, error) {
	// Generate ECDSA private key
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type")
	}

	// Create a template for the certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: lsvid.SubjectID,
		},
		NotBefore:             time.Now(),
		NotAfter:              lsvid.SubjectKeyExpiration,
		BasicConstraintsValid: true,
	}

	// Set the public key in the certificate template
	template.PublicKey = ecdsaPrivateKey.Public()

	// Add the "localhost" hostname to the certificate's Subject Alternative Name (SAN)
	template.DNSNames = []string{"localhost"}

	// Generate a random serial number for the certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}
	template.SerialNumber = serialNumber

	// Sign the certificate with the private key to generate the final certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, ecdsaPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the private key and certificate bytes to PEM format
	marshKey, _ := x509.MarshalECPrivateKey(ecdsaPrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshKey})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// Concatenate the key and certificate PEM data
	pemData := append(keyPEM, certPEM...)

	return pemData, nil
}

func main() {
	// Generate an ECDSA private key for the server
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create the server LSVID
	serverLSVID := LSVID{
		Version:              "1",
		IssuerID:             "spiffe://example.org/",
		SubjectID:            "spiffe://example.org/server",
		SubjectPublicKey:     privateKey.Public(),
		SubjectKeyExpiration: time.Now().Add(24 * time.Hour).UTC(),
		Signature:            nil,
	}

	// Create an HTTP server with LSVID-based mTLS
	err = ListenAndServeLSVID(":8080", http.HandlerFunc(ServeHTTP), serverLSVID, privateKey)
	if err != nil {
		log.Fatalf("Failed to start LSVID-based mTLS server: %v", err)
	}
}

// VerifyPeerCertificate is a custom callback function for verifying client certificates
func VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	clientCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %v", err)
	}

	// Verify LSVID of the client
	if !verifyLSVID(clientCert.Subject.CommonName) {
		return fmt.Errorf("invalid client LSVID")
	}

	// Compute the hash of the certificate's raw TBSCertificate
	tbs := clientCert.RawTBSCertificate
	hash := sha256.Sum256(tbs)

	// Verify the signature using the public key
	if !ecdsa.VerifyASN1(clientCert.PublicKey.(*ecdsa.PublicKey), hash[:], clientCert.Signature) {
		return fmt.Errorf("Invalid certificate signature: %v", err)
	}
	log.Println("Client certificate signature successfully validated!")

	// comparar a chave publca do cert com chave publica do LSVID, vinculando-os
	// if clientCert.PublicKey == LSVID.PublicKey
	log.Println("TODO: ADD if clientCert.PublicKey == LSVID.PublicKey to validate the link")

	return nil
}