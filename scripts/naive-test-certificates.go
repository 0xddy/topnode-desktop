// Generate ephemeral TLS fixtures for verify-naive.py using only the Go standard library.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"time"
)

type testCertificate struct {
	certificate string
	template    *x509.Certificate
	key         *rsa.PrivateKey
}

func generateCertificate(name string, notBefore, notAfter time.Time, isCA bool, issuer *testCertificate) testCertificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate key for %q: %v", name, err)
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign
	} else {
		template.DNSNames = []string{name}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	parent, signingKey := template, key
	if issuer != nil {
		parent, signingKey = issuer.template, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signingKey)
	if err != nil {
		log.Fatalf("create certificate for %q: %v", name, err)
	}
	return testCertificate{
		certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		template:    template,
		key:         key,
	}
}

type serverPEM struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

func (cert testCertificate) serverPEM() serverPEM {
	der, err := x509.MarshalPKCS8PrivateKey(cert.key)
	if err != nil {
		log.Fatalf("encode key for %q: %v", cert.template.Subject.CommonName, err)
	}
	return serverPEM{
		Certificate: cert.certificate,
		Key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: naive-test-certificates SERVER_NAME")
	}
	name := os.Args[1]
	now := time.Now().UTC()
	notBefore, notAfter := now.AddDate(0, 0, -2), now.AddDate(0, 0, 1)
	ca := generateCertificate("Desktop Naive test CA", notBefore, notAfter, true, nil)
	otherCA := generateCertificate("Wrong Naive test CA", notBefore, notAfter, true, nil)
	leaf := generateCertificate(name, notBefore, notAfter, false, &ca)
	selfSigned := generateCertificate(name, notBefore, notAfter, false, nil)
	expired := generateCertificate(name, notBefore, now.AddDate(0, 0, -1), false, &ca)

	fixtures := struct {
		CA         string    `json:"ca"`
		OtherCA    string    `json:"other_ca"`
		Leaf       serverPEM `json:"leaf"`
		SelfSigned serverPEM `json:"self_signed"`
		Expired    serverPEM `json:"expired"`
	}{
		CA:         ca.certificate,
		OtherCA:    otherCA.certificate,
		Leaf:       leaf.serverPEM(),
		SelfSigned: selfSigned.serverPEM(),
		Expired:    expired.serverPEM(),
	}
	if err := json.NewEncoder(os.Stdout).Encode(fixtures); err != nil {
		log.Fatalf("write TLS fixtures: %v", err)
	}
}
