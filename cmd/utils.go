package cmd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"i2pgit.org/go-i2p/reseed-tools/reseed"
	"i2pgit.org/go-i2p/reseed-tools/su3"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	privPem, err := ioutil.ReadFile(path)
	if nil != err {
		lgr.WithError(err).WithField("key_path", path).Error("Failed to read private key file")
		return nil, err
	}

	privDer, _ := pem.Decode(privPem)
	privKey, err := x509.ParsePKCS1PrivateKey(privDer.Bytes)
	if nil != err {
		lgr.WithError(err).WithField("key_path", path).Error("Failed to parse private key")
		return nil, err
	}

	return privKey, nil
}

// signerFile creates a filename-safe version of a signer ID.
// This function provides consistent filename generation across the cmd package.
func signerFile(signerID string) string {
	return strings.Replace(signerID, "@", "_at_", 1)
}

func getOrNewSigningCert(signerKey *string, signerID string, auto bool) (*rsa.PrivateKey, error) {
	// Check if signing key file exists before attempting to load
	if _, err := os.Stat(*signerKey); nil != err {
		lgr.WithError(err).WithField("signer_key", *signerKey).WithField("signer_id", signerID).Debug("Signing key file not found, prompting for generation")
		fmt.Printf("Unable to read signing key '%s'\n", *signerKey)
		// Prompt user for key generation in interactive mode
		if !auto {
			fmt.Printf("Would you like to generate a new signing key for %s? (y or n): ", signerID)
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			if []byte(input)[0] != 'y' {
				lgr.WithField("signer_id", signerID).Error("User declined to generate signing key")
				return nil, fmt.Errorf("a signing key is required")
			}
		}
		// Generate new signing certificate if user confirmed or auto mode
		if err := createSigningCertificate(signerID); nil != err {
			lgr.WithError(err).WithField("signer_id", signerID).Error("Failed to create signing certificate")
			return nil, err
		}

		// Update key path to point to newly generated certificate
		*signerKey = signerFile(signerID) + ".pem"
	}

	return loadPrivateKey(*signerKey)
}

func checkUseAcmeCert(tlsHost, signer, cadirurl string, tlsCert, tlsKey *string, auto bool) error {
	// Check if certificate files exist and handle missing files
	needsNewCert, err := checkAcmeCertificateFiles(tlsCert, tlsKey, tlsHost, auto)
	if err != nil {
		return err
	}

	// If files exist, check if certificate needs renewal
	if !needsNewCert {
		shouldRenew, err := checkAcmeCertificateRenewal(tlsCert, tlsKey, tlsHost, signer, cadirurl)
		if err != nil {
			return err
		}
		if !shouldRenew {
			return nil
		}
	}

	// Generate new ACME certificate
	return generateNewAcmeCertificate(tlsHost, signer, cadirurl, tlsCert, tlsKey)
}

// checkAcmeCertificateFiles verifies certificate file existence and prompts for generation if needed.
func checkAcmeCertificateFiles(tlsCert, tlsKey *string, tlsHost string, auto bool) (bool, error) {
	_, certErr := os.Stat(*tlsCert)
	_, keyErr := os.Stat(*tlsKey)

	if certErr != nil || keyErr != nil {
		if certErr != nil {
			fmt.Printf("Unable to read TLS certificate '%s'\n", *tlsCert)
		}
		if keyErr != nil {
			fmt.Printf("Unable to read TLS key '%s'\n", *tlsKey)
		}

		if !auto {
			fmt.Printf("Would you like to generate a new certificate with Let's Encrypt or a custom ACME server? '%s'? (y or n): ", tlsHost)
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			if []byte(input)[0] != 'y' {
				fmt.Println("Continuing without TLS")
				return false, nil
			}
		}
		return true, nil
	}

	return false, nil
}

// checkAcmeCertificateRenewal loads existing certificate and checks if renewal is needed.
func checkAcmeCertificateRenewal(tlsCert, tlsKey *string, tlsHost, signer, cadirurl string) (bool, error) {
	tlsConfig := &tls.Config{}
	tlsConfig.NextProtos = []string{"http/1.1"}
	tlsConfig.Certificates = make([]tls.Certificate, 1)

	var err error
	tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		return false, err
	}

	// Parse the certificate to populate the Leaf field if it's nil
	if tlsConfig.Certificates[0].Leaf == nil && len(tlsConfig.Certificates[0].Certificate) > 0 {
		cert, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
		if err != nil {
			return false, fmt.Errorf("failed to parse certificate: %w", err)
		}
		tlsConfig.Certificates[0].Leaf = cert
	}

	// Check if certificate expires within 48 hours (time until expiration < 48 hours)
	if tlsConfig.Certificates[0].Leaf != nil && time.Until(tlsConfig.Certificates[0].Leaf.NotAfter) < (time.Hour*48) {
		return renewExistingAcmeCertificate(tlsHost, signer, cadirurl, tlsCert, tlsKey)
	}

	return false, nil
}

// renewExistingAcmeCertificate loads existing ACME key and renews the certificate.
func renewExistingAcmeCertificate(tlsHost, signer, cadirurl string, tlsCert, tlsKey *string) (bool, error) {
	ecder, err := ioutil.ReadFile(tlsHost + signer + ".acme.key")
	if err != nil {
		return false, err
	}

	privateKey, err := x509.ParseECPrivateKey(ecder)
	if err != nil {
		return false, err
	}

	user := NewMyUser(signer, privateKey)
	config := lego.NewConfig(user)
	config.CADirURL = cadirurl
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return false, err
	}

	err = renewAcmeIssuedCert(client, *user, tlsHost, tlsCert, tlsKey)
	return true, err
}

// generateNewAcmeCertificate creates a new ACME private key and obtains a certificate.
func generateNewAcmeCertificate(tlsHost, signer, cadirurl string, tlsCert, tlsKey *string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	if err := saveAcmePrivateKey(privateKey, tlsHost, signer); err != nil {
		return err
	}

	user := NewMyUser(signer, privateKey)
	config := lego.NewConfig(user)
	config.CADirURL = cadirurl
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	return newAcmeIssuedCert(client, *user, tlsHost, tlsCert, tlsKey)
}

// saveAcmePrivateKey marshals and saves the ACME private key to disk.
func saveAcmePrivateKey(privateKey *ecdsa.PrivateKey, tlsHost, signer string) error {
	ecder, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	filename := tlsHost + signer + ".acme.key"
	keypem, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer keypem.Close()

	return pem.Encode(keypem, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecder})
}

func renewAcmeIssuedCert(client *lego.Client, user MyUser, tlsHost string, tlsCert, tlsKey *string) error {
	var err error
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "8000"))
	if err != nil {
		return err
	}
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "8443"))
	if err != nil {
		return err
	}

	// New users will need to register
	if user.Registration, err = client.Registration.QueryRegistration(); err != nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		user.Registration = reg
	}
	resource, err := client.Certificate.Get(tlsHost, true)
	if err != nil {
		return err
	}
	certificates, err := client.Certificate.Renew(*resource, true, false, "")
	if err != nil {
		return err
	}

	ioutil.WriteFile(tlsHost+".pem", certificates.PrivateKey, 0o600)
	ioutil.WriteFile(tlsHost+".crt", certificates.Certificate, 0o600)
	//	ioutil.WriteFile(tlsHost+".crl", certificates.PrivateKey, 0600)
	*tlsCert = tlsHost + ".crt"
	*tlsKey = tlsHost + ".pem"
	return nil
}

func newAcmeIssuedCert(client *lego.Client, user MyUser, tlsHost string, tlsCert, tlsKey *string) error {
	var err error
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "8000"))
	if err != nil {
		return err
	}
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "8443"))
	if err != nil {
		return err
	}

	// New users will need to register
	if user.Registration, err = client.Registration.QueryRegistration(); err != nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		user.Registration = reg
	}

	request := certificate.ObtainRequest{
		Domains: []string{tlsHost},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	ioutil.WriteFile(tlsHost+".pem", certificates.PrivateKey, 0o600)
	ioutil.WriteFile(tlsHost+".crt", certificates.Certificate, 0o600)
	//	ioutil.WriteFile(tlsHost+".crl", certificates.PrivateKey, 0600)
	*tlsCert = tlsHost + ".crt"
	*tlsKey = tlsHost + ".pem"
	return nil
}

func checkOrNewTLSCert(tlsHost string, tlsCert, tlsKey *string, auto bool) error {
	_, certErr := os.Stat(*tlsCert)
	_, keyErr := os.Stat(*tlsKey)
	if certErr != nil || keyErr != nil {
		if certErr != nil {
			fmt.Printf("Unable to read TLS certificate '%s'\n", *tlsCert)
		}
		if keyErr != nil {
			fmt.Printf("Unable to read TLS key '%s'\n", *tlsKey)
		}

		if !auto {
			fmt.Printf("Would you like to generate a new self-signed certificate for '%s'? (y or n): ", tlsHost)
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			if []byte(input)[0] != 'y' {
				fmt.Println("Continuing without TLS")
				return nil
			}
		}

		if err := createTLSCertificate(tlsHost); nil != err {
			return err
		}

		*tlsCert = tlsHost + ".crt"
		*tlsKey = tlsHost + ".pem"
	}

	return nil
}

// createSigningCertificate generates a new RSA private key and self-signed certificate for SU3 signing.
// This function creates the cryptographic materials needed to sign SU3 files for distribution
// over the I2P network. The generated certificate is valid for 10 years and uses 4096-bit RSA keys.
func createSigningCertificate(signerID string) error {
	// Generate 4096-bit RSA private key for strong cryptographic security
	signerKey, err := generateSigningPrivateKey()
	if err != nil {
		return err
	}

	// Create self-signed certificate using SU3 certificate standards
	signerCert, err := su3.NewSigningCertificate(signerID, signerKey)
	if nil != err {
		return err
	}

	// Save certificate to disk in PEM format for verification use
	if err := saveSigningCertificateFile(signerID, signerCert); err != nil {
		return err
	}

	// Save signing private key in PKCS#1 PEM format with certificate bundle
	if err := saveSigningPrivateKeyFile(signerID, signerKey, signerCert); err != nil {
		return err
	}

	// Generate and save Certificate Revocation List (CRL)
	if err := generateAndSaveSigningCRL(signerID, signerKey, signerCert); err != nil {
		return err
	}

	return nil
}

// generateSigningPrivateKey creates a new 4096-bit RSA private key for SU3 signing.
// Returns the generated private key or an error if key generation fails.
func generateSigningPrivateKey() (*rsa.PrivateKey, error) {
	fmt.Println("Generating signing keys. This may take a minute...")
	signerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return signerKey, nil
}

// saveSigningCertificateFile saves the signing certificate to disk in PEM format.
// The certificate is saved as <signerID>.crt for verification use.
func saveSigningCertificateFile(signerID string, signerCert []byte) error {
	certFile := signerFile(signerID) + ".crt"
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certFile, err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert})
	fmt.Println("\tSigning certificate saved to:", certFile)
	return nil
}

// saveSigningPrivateKeyFile saves the signing private key in PKCS#1 PEM format with certificate bundle.
// The private key is saved as <signerID>.pem with the certificate included for convenience.
func saveSigningPrivateKeyFile(signerID string, signerKey *rsa.PrivateKey, signerCert []byte) error {
	privFile := signerFile(signerID) + ".pem"
	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", privFile, err)
	}
	defer keyOut.Close()

	// Write RSA private key in PKCS#1 format
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signerKey)})

	// Include certificate in the key file for convenience
	pem.Encode(keyOut, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert})

	fmt.Println("\tSigning private key saved to:", privFile)
	return nil
}

// generateAndSaveSigningCRL generates and saves a Certificate Revocation List (CRL) for the signing certificate.
// The CRL is saved as <signerID>.crl and includes the certificate as revoked for testing purposes.
func generateAndSaveSigningCRL(signerID string, signerKey *rsa.PrivateKey, signerCert []byte) error {
	crlFile := signerFile(signerID) + ".crl"
	crlOut, err := os.OpenFile(crlFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", crlFile, err)
	}
	defer crlOut.Close()

	// Parse the certificate to extract information for CRL
	crlcert, err := x509.ParseCertificate(signerCert)
	if err != nil {
		return fmt.Errorf("certificate with unknown critical extension was not parsed: %s", err)
	}

	// Create revoked certificate entry for testing purposes
	now := time.Now()
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   crlcert.SerialNumber,
			RevocationTime: now,
		},
	}

	// Generate CRL bytes
	crlBytes, err := crlcert.CreateCRL(rand.Reader, signerKey, revokedCerts, now, now)
	if err != nil {
		return fmt.Errorf("error creating CRL: %s", err)
	}

	// Validate CRL by parsing it
	if _, err := x509.ParseDERCRL(crlBytes); err != nil {
		return fmt.Errorf("error reparsing CRL: %s", err)
	}

	// Save CRL to file
	pem.Encode(crlOut, &pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	fmt.Printf("\tSigning CRL saved to: %s\n", crlFile)
	return nil
}

func createTLSCertificate(host string) error {
	return CreateTLSCertificate(host)
}

// CreateTLSCertificate generates a new ECDSA private key and self-signed TLS certificate.
// This function creates cryptographic materials for HTTPS server operation, using P-384 elliptic
// curve cryptography for efficient and secure TLS connections. The certificate is valid for the specified hostname.
func CreateTLSCertificate(host string) error {
	// Generate P-384 ECDSA private key for TLS encryption
	priv, err := generateTLSPrivateKey()
	if err != nil {
		return err
	}

	// Create self-signed TLS certificate for the specified hostname
	tlsCert, err := reseed.NewTLSCertificate(host, priv)
	if nil != err {
		return err
	}

	// Save TLS certificate to disk in PEM format for server use
	if err := saveTLSCertificateFile(host, tlsCert); err != nil {
		return err
	}

	// Save the TLS private key with EC parameters and certificate bundle
	if err := saveTLSPrivateKeyFile(host, priv, tlsCert); err != nil {
		return err
	}

	// Generate and save Certificate Revocation List (CRL)
	if err := generateAndSaveTLSCRL(host, priv, tlsCert); err != nil {
		return err
	}

	return nil
}

// generateTLSPrivateKey creates a new P-384 ECDSA private key for TLS encryption.
// Returns the generated private key or an error if key generation fails.
func generateTLSPrivateKey() (*ecdsa.PrivateKey, error) {
	fmt.Println("Generating TLS keys. This may take a minute...")
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// saveTLSCertificateFile saves the TLS certificate to disk in PEM format.
// The certificate is saved as <host>.crt for server use.
func saveTLSCertificateFile(host string, tlsCert []byte) error {
	certFile := host + ".crt"
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", certFile, err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert})
	fmt.Printf("\tTLS certificate saved to: %s\n", certFile)
	return nil
}

// saveTLSPrivateKeyFile saves the TLS private key with EC parameters and certificate bundle.
// The private key is saved as <host>.pem with proper EC parameters and certificate included.
func saveTLSPrivateKeyFile(host string, priv *ecdsa.PrivateKey, tlsCert []byte) error {
	privFile := host + ".pem"
	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", privFile, err)
	}
	defer keyOut.Close()

	// Encode secp384r1 curve parameters
	secp384r1, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}) // http://www.ietf.org/rfc/rfc5480.txt
	if err != nil {
		return fmt.Errorf("failed to marshal EC parameters: %v", err)
	}

	// Write EC parameters block
	pem.Encode(keyOut, &pem.Block{Type: "EC PARAMETERS", Bytes: secp384r1})

	// Marshal and write EC private key
	ecder, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal EC private key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecder})

	// Include certificate in the key file
	pem.Encode(keyOut, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert})

	fmt.Printf("\tTLS private key saved to: %s\n", privFile)
	return nil
}

// generateAndSaveTLSCRL generates and saves a Certificate Revocation List (CRL) for the TLS certificate.
// The CRL is saved as <host>.crl and includes the certificate as revoked for testing purposes.
func generateAndSaveTLSCRL(host string, priv *ecdsa.PrivateKey, tlsCert []byte) error {
	crlFile := host + ".crl"
	crlOut, err := os.OpenFile(crlFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", crlFile, err)
	}
	defer crlOut.Close()

	// Parse the certificate to extract information for CRL
	crlcert, err := x509.ParseCertificate(tlsCert)
	if err != nil {
		return fmt.Errorf("certificate with unknown critical extension was not parsed: %s", err)
	}

	// Create revoked certificate entry for testing purposes
	now := time.Now()
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   crlcert.SerialNumber,
			RevocationTime: now,
		},
	}

	// Generate CRL bytes
	crlBytes, err := crlcert.CreateCRL(rand.Reader, priv, revokedCerts, now, now)
	if err != nil {
		return fmt.Errorf("error creating CRL: %s", err)
	}

	// Validate CRL by parsing it
	if _, err := x509.ParseDERCRL(crlBytes); err != nil {
		return fmt.Errorf("error reparsing CRL: %s", err)
	}

	// Save CRL to file
	pem.Encode(crlOut, &pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	fmt.Printf("\tTLS CRL saved to: %s\n", crlFile)
	return nil
}
