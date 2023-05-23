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
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
)

// LSVID structure representing the LSVID identity
type LSVID struct {
	Version              string
	IssuerID             string
	SubjectID            string
	SubjectPublicKey     []byte
	SubjectKeyExpiration time.Time
	Signature            []byte
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (lsvid *LSVID) toString() (string, error) {
	// Convert the LSVID struct to JSON
	jsonData, err := json.Marshal(lsvid)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal LSVID to JSON: %v\n", err)
	}

	// Encode the JSON data to base64
	encLSVID := base64.StdEncoding.EncodeToString(jsonData)
	return encLSVID, nil
}

func main() {

	// Generate an ECDSA private key for the server
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create a dummy server LSVID
	serverID := "spiffe://example.org/server"
	log.Printf("Server ID: %s\n", serverID)
	serverLSVID, err := createLSVID(serverID, privateKey)
	if err != nil {
		log.Fatalf("Error generating LSVID: %v", err)
	}

	// Create an HTTP server with LSVID-based mTLS
	err = ListenAndServeLSVID(":8080", http.HandlerFunc(ServeHTTP), serverLSVID, privateKey)
	if err != nil {
		log.Fatalf("Failed to start LSVID-based mTLS server: %v", err)
	}
}

// ListenAndServeLSVID listens on the specified address and handles incoming LSVID-based mTLS requests
func ListenAndServeLSVID(addr string, handler http.Handler, serverLSVID string, privateKey crypto.PrivateKey) error {

	log.Printf("Server LSVID: %s", serverLSVID)

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

// ServeHTTP handles incoming HTTP requests
func ServeHTTP(w http.ResponseWriter, r *http.Request) {

	clientcert := r.TLS.PeerCertificates[0]
	log.Println("Received request from client: ", clientcert.Subject.CommonName)
	
	receivedLSVID := r.Header.Get("LSVID")
	log.Println("Received client LSVID: ", receivedLSVID)

	clientLSVID,err := stringToLSVID(receivedLSVID)
	if err != nil {
		log.Fatalf("Error decoding base64 LSVID: %s", err)
	}

	// Compare public keys
	if !comparePK(clientLSVID, clientcert) {
		log.Println("Public keys does not match")
		http.Error(w, "Public keys does not match", http.StatusUnauthorized)
		return
	}

	// Verify client LSVID
	if !verifyLSVID(receivedLSVID) {
		log.Println("Invalid client LSVID")
		http.Error(w, "Invalid client LSVID", http.StatusUnauthorized)
		return
	}

	// Extract the raw client certificate
	rawCert := clientcert.Raw

	// Verify client certificate signature
	if err := VerifyPeerCertificate([][]byte{rawCert}, r.TLS.VerifiedChains); err != nil {
		log.Println("Invalid client certificate:", err)
		http.Error(w, "Invalid client certificate", http.StatusUnauthorized)
		return
	}
	log.Println("Valid client LSVID!")

	// Send a message from the server to the client
	message := "Successfull secure connection between " + clientcert.Subject.CommonName + " and server!"
	_, err = w.Write([]byte(message))
	if err != nil {
		log.Printf("Failed to send message to client: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("Message sent to client: %s \n", message)
}


// Helper function to verify LSVID
func verifyLSVID(lsvid string) bool {
	// TODO: Implement LSVID verification logic
	// ...
	// LSVID exp, signature and bundle validation... 
	return true
}

// GenerateCertificate generates a self-signed X.509 certificate based on the LSVID data
// TODO: Add swith algorithm
func GenerateCertificate(clientLSVID string, privateKey crypto.PrivateKey) ([]byte, error) {

	// Decode the base64-encoded LSVID
	lsvid, err := stringToLSVID(clientLSVID)
	if err != nil {
		log.Fatalf("Error decoding base64 LSVID: %s", err)
	}

	// Parse the public key from the LSVID bytes
	publicKey, err := x509.ParsePKIXPublicKey(lsvid.SubjectPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error parsing public key: %v", err)
	}

	// Type assert the parsed public key to get the ECDSA public key
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Invalid public key type")
	}
	
	// assign ECDSA private key
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type")
	}

	// Generate a random serial number for the certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Create a template for the certificate
	template := &x509.Certificate{
		SerialNumber:			serialNumber,
		Subject:				pkix.Name{
									CommonName: lsvid.SubjectID,
								},
		NotBefore:				time.Now(),
		NotAfter:				lsvid.SubjectKeyExpiration,
		BasicConstraintsValid:	true,
		PublicKey:				ecdsaPublicKey,
		DNSNames:				[]string{"localhost"},
	}

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


// VerifyPeerCertificate is a custom callback function for verifying client certificates
func VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	clientCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %v", err)
	}

	// Compute the hash of the certificate's raw TBSCertificate
	tbs := clientCert.RawTBSCertificate
	hash := sha256.Sum256(tbs)

	// Verify the cert signature using the cert public key
	if !ecdsa.VerifyASN1(clientCert.PublicKey.(*ecdsa.PublicKey), hash[:], clientCert.Signature) {
		return fmt.Errorf("Invalid certificate signature: %v", err)
	}
	log.Println("Client certificate signature successfully validated!")

	return nil
}

func createLSVID(id string, privateKey crypto.PrivateKey) (string, error) {
	// Type assert privateKey to get the ECDSA private key
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("Invalid private key type")
	}
	
	// Convert the ECDSA public key to bytes
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPrivateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("Error marshaling public key: %v", err)
	}

	// Create the LSVID payload
	reqLSVID := LSVID{
		Version:              "1",
		IssuerID:             "spiffe://example.org/",
		SubjectID:            id,
		SubjectPublicKey:     publicKeyBytes,
		SubjectKeyExpiration: time.Now().Add(24 * time.Hour).UTC(),
	}

	// Sign the LSVID payload
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s", reqLSVID)))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("Error signing LSVID payload: %s\n", err)
	}

	// Encode the ECDSA signature
	signatureBytes, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return "", fmt.Errorf("Error encoding ECDSA signature: %s\n", err)
	}
	
	// Add signature to req LSVID
	reqLSVID.Signature = signatureBytes
	
	encLSVID, err := reqLSVID.toString()
	if err != nil {
		return "", fmt.Errorf("Error encoding LSVID: %s\n", err)
	}

	return encLSVID, nil
}

func stringToLSVID(encLSVID string) (LSVID, error) {

	// Decode the base64-encoded LSVID
	decLSVID, err := base64.StdEncoding.DecodeString(encLSVID)
	if err != nil {
		log.Fatalf("Error decoding base64 LSVID: %s", err)
	}

	// Parse the JSON string into an LSVID struct
	var lsvid LSVID
	err = json.Unmarshal(decLSVID, &lsvid)
	if err != nil {
		log.Fatalf("Error parsing LSVID JSON: %s", err)
	}
	return lsvid, nil
}

func comparePK(lsvid LSVID, certificate *x509.Certificate) bool {

	// Parse the public key from the LSVID bytes
	publicKey, err := x509.ParsePKIXPublicKey(lsvid.SubjectPublicKey)
	if err != nil {
		log.Println("Error parsing public key: %v", err)
		return false
	}

	// Type assert the parsed public key to get the ECDSA public key
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Println("Invalid public key type")
		return false
	}

	// Check if both Public keys are the same
	if !(ecdsaPublicKey.Equal(certificate.PublicKey)) {
		return false
	}
	log.Println("Certificate and LSVID public keys matches!")
	return true
}