package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/micromdm/scep/v2/cryptoutil/x509util"
	scepserver "github.com/micromdm/scep/v2/server"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

func main() {
	url := flag.String("url", "", "HTTPS SCEP endpoint")
	method := flag.String("method", "POST", "PKIOperation HTTP method")
	mode := flag.String("mode", "enroll", "enroll, renew, changed-subject, replay")
	challenge := flag.String("challenge", "", "initial enrollment challenge")
	subject := flag.String("subject", "iq-micromdm", "device common name")
	expected := flag.String("expect", "success", "success or badRequest")
	flag.Parse()
	if err := run(*url, *method, *mode, *challenge, *subject, *expected); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(url, method, mode, challenge, subject, expected string) error {
	if !strings.HasPrefix(url, "https://") || (method != "GET" && method != "POST") {
		return fmt.Errorf("require HTTPS and GET or POST")
	}
	if mode != "enroll" && mode != "renew" && mode != "changed-subject" && mode != "replay" {
		return fmt.Errorf("unknown mode %q", mode)
	}
	if expected != "success" && expected != "badRequest" {
		return fmt.Errorf("unknown expected outcome %q", expected)
	}
	http.DefaultClient.Timeout = 20 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client, err := scepserver.MakeClientEndpoints(url)
	if err != nil {
		return err
	}
	caps, err := client.GetCACaps(ctx)
	if err != nil {
		return err
	}
	for _, capability := range []string{"AES", "SHA-256", "POSTPKIOperation", "Renewal", "SCEPStandard"} {
		if !strings.Contains("\n"+string(caps), "\n"+capability+"\n") {
			return fmt.Errorf("missing capability %s: %s", capability, caps)
		}
	}
	bundle, count, err := client.GetCACert(ctx, "")
	if err != nil {
		return err
	}
	if count < 2 {
		return fmt.Errorf("expected CA/RA bundle, got %d", count)
	}
	certs, err := scep.CACerts(bundle)
	if err != nil {
		return err
	}
	if err := os.WriteFile("ca.der", bundle, 0600); err != nil {
		return err
	}
	// The external SDK defaults to DES. RFC 8894 AES-CBC is selected via its public API.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	if method == "GET" {
		client.PostEndpoint = client.GetEndpoint
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	name := pkix.Name{CommonName: subject}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: name,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	signer, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	request, err := newRequest(key, signer, key, certs, name, challenge, scep.PKCSReq)
	if err != nil {
		return err
	}
	outcome := expected
	if mode != "enroll" {
		outcome = "success"
	}
	issued, err := exchange(ctx, client, request, signer, key, certs, outcome)
	if err != nil {
		return err
	}
	if mode == "replay" {
		_, err = exchange(ctx, client, request, signer, key, certs, "badRequest")
		return err
	}
	if mode == "renew" || mode == "changed-subject" {
		if err := writePEM("previous.pem", "CERTIFICATE", issued.Raw); err != nil {
			return err
		}
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		if mode == "changed-subject" {
			name.CommonName += "-impostor"
		}
		request, err = newRequest(newKey, issued, key, certs, name, "", scep.RenewalReq)
		if err != nil {
			return err
		}
		renewed, err := exchange(ctx, client, request, issued, key, certs, expected)
		if err != nil {
			return err
		}
		if renewed == nil {
			return nil
		}
		if renewed.SerialNumber.Cmp(issued.SerialNumber) == 0 {
			return fmt.Errorf("renewal reused the old serial")
		}
		issued, key = renewed, newKey
	}
	if issued == nil {
		return nil
	}
	if err := writePEM("cert.pem", "CERTIFICATE", issued.Raw); err != nil {
		return err
	}
	return writePEM("key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
}

func newRequest(csrKey *rsa.PrivateKey, signer *x509.Certificate, signerKey *rsa.PrivateKey,
	certs []*x509.Certificate, name pkix.Name, challenge string, kind scep.MessageType) (*scep.PKIMessage, error) {
	template := &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{Subject: name, SignatureAlgorithm: x509.SHA256WithRSA},
		ChallengePassword:  challenge,
	}
	der, err := x509util.CreateCertificateRequest(rand.Reader, template, csrKey)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	return scep.NewCSRRequest(csr, &scep.PKIMessage{
		MessageType: kind, Recipients: certs, SignerCert: signer, SignerKey: signerKey,
	}, scep.WithCertsSelector(scep.EnciphermentCertsSelector()))
}

func exchange(ctx context.Context, client *scepserver.Endpoints, request *scep.PKIMessage,
	signer *x509.Certificate, key *rsa.PrivateKey, caCerts []*x509.Certificate, expected string) (*x509.Certificate, error) {
	raw, err := client.PKIOperation(ctx, request.Raw)
	if err != nil {
		return nil, err
	}
	reply, err := scep.ParsePKIMessage(raw, scep.WithCACerts(request.Recipients))
	if err != nil {
		return nil, err
	}
	if reply.MessageType != scep.CertRep || reply.TransactionID != request.TransactionID ||
		reply.CertRepMessage == nil || !bytes.Equal(reply.RecipientNonce, request.SenderNonce) {
		return nil, fmt.Errorf("CertRep does not match transaction and sender nonce")
	}
	requestName := map[scep.MessageType]string{scep.PKCSReq: "PKCSReq", scep.RenewalReq: "RenewalReq"}[request.MessageType]
	statusName := map[scep.PKIStatus]string{scep.SUCCESS: "SUCCESS", scep.FAILURE: "FAILURE", scep.PENDING: "PENDING"}[reply.PKIStatus]
	failInfo := ""
	if reply.PKIStatus == scep.FAILURE {
		failInfo = reply.FailInfo.String()
	}
	fmt.Printf("request=%s status=%s failInfo=%s\n", requestName, statusName, failInfo)
	if expected == "badRequest" {
		if reply.PKIStatus != scep.FAILURE || reply.FailInfo != scep.BadRequest {
			return nil, fmt.Errorf("expected signed badRequest refusal")
		}
		return nil, nil
	}
	if reply.PKIStatus != scep.SUCCESS {
		return nil, fmt.Errorf("expected SUCCESS, got %s (%s)", reply.PKIStatus, reply.FailInfo)
	}
	if err := reply.DecryptPKIEnvelope(signer, key); err != nil {
		return nil, err
	}
	cert := reply.Certificate
	if cert == nil || !bytes.Equal(cert.RawSubject, request.CSR.RawSubject) ||
		!bytes.Equal(cert.RawSubjectPublicKeyInfo, request.CSR.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("issued certificate does not match CSR subject and public key")
	}
	roots := x509.NewCertPool()
	for _, ca := range caCerts {
		if ca.IsCA {
			roots.AddCert(ca)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("issued certificate does not chain to GetCACert: %w", err)
	}
	return cert, nil
}

func writePEM(path, kind string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0600)
}
