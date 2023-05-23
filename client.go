package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/elliptic"

	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"time"

	"encoding/asn1"
	"crypto/sha256"
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

	// Generate an ECDSA private key for the client
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create the LSVID to a given ID/Privatekey
	clientID := "spiffe://example.org/client"
	log.Printf("Client ID: %s\n", clientID)

	clientLSVID, err := createLSVID(clientID, privateKey)
	if err != nil {
		log.Fatalf("Error generating LSVID: %v", err)
	}
	log.Printf("Client LSVID: %s", clientLSVID)

	// Generate a self-signed X.509 certificate based on the LSVID data
	certBytes, err := GenerateCertificate(clientLSVID, privateKey)
	if err != nil {
		log.Fatalf("failed to generate certificate: %v", err)
	}

	// Create a new TLS certificate using the generated certificate bytes and private key
	cert, err := tls.X509KeyPair(certBytes, certBytes)
	if err != nil {
		log.Fatalf("failed to create TLS certificate: %v", err)
	}
	
	// Create a TLS configuration with the loaded client certificate
	tlsConfig := &tls.Config{
		InsecureSkipVerify:		true,
		Certificates:			[]tls.Certificate{cert},
		ClientAuth:   			tls.VerifyClientCertIfGiven,
		VerifyPeerCertificate:	VerifyPeerCertificate,
	}

	// Create a transport with the TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{Transport: transport}

	// Add LSVID to the request header
	req, err := http.NewRequest("GET", "https://localhost:8080", nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("LSVID", clientLSVID)
	
	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body and print the server's message
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Println("Server's message:", string(body))
}


// GenerateCertificate generates a self-signed X.509 certificate based on the LSVID data
func GenerateCertificate(clientLSVID string, privateKey crypto.PrivateKey) ([]byte, error) {

	// Decode the base64-encoded LSVID
	lsvid, err := stringToLSVID(clientLSVID)
	if err != nil {
		log.Fatalf("Error parsing LSVID JSON: %s", err)
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

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %v", err)
	}

	// Compute the hash of the certificate's raw TBSCertificate
	tbs := cert.RawTBSCertificate
	hash := sha256.Sum256(tbs)

	// Verify the cert signature using the cert public key
	if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), hash[:], cert.Signature) {
		return fmt.Errorf("Invalid certificate signature: %v", err)
	}
	log.Printf("%s certificate signature successfully validated!\n", cert.Subject)

	return nil
}

// Helper function to verify LSVID
func verifyLSVID(lsvid string) bool {
	// TODO: Implement LSVID verification logic
	// ...

	// Placeholder LSVID verification
	return true
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

	// Convert LSVID to string
	encLSVID, err:= reqLSVID.toString()
	if err != nil {
		return "", fmt.Errorf("Failed to marshal LSVID to JSON: %v\n", err)
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