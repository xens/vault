package cassandra

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
)

// ParsePEMBundle takes a string of concatenated PEM-format certificate
// and private key values and decodes/parses them, checking validity along
// the way. The first certificate must be the subject certificate and issuing
// certificates may follow.  There must be at most one private key.
// NOTE: This is a copy-paste from the sdk/helper/certutil package but with changes to it
//       The certutil version assumes that a non-CA certificate is provided and the first
//       certificate found in the PEM bundle is that certificate, even if that certificate
//       is actually a CA. This version checks to see if the certificate is a CA and adds
//       it to the CAChain instead. This allows for specifying: a cert, private key, or CA
//       chain independently of each other.
func ParsePEMBundle(pemBundle string) (*certutil.ParsedCertBundle, error) {
	if len(pemBundle) == 0 {
		return nil, errutil.UserError{Err: "empty pem bundle"}
	}

	pemBytes := []byte(pemBundle)
	var pemBlock *pem.Block
	parsedBundle := &certutil.ParsedCertBundle{}
	var certPath []*certutil.CertBlock

	for len(pemBytes) > 0 {
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			return nil, errutil.UserError{Err: "no data found in PEM block"}
		}

		if signer, err := x509.ParseECPrivateKey(pemBlock.Bytes); err == nil {
			if parsedBundle.PrivateKeyType != certutil.UnknownPrivateKey {
				return nil, errutil.UserError{Err: "more than one private key given; provide only one private key in the bundle"}
			}
			parsedBundle.PrivateKeyFormat = certutil.ECBlock
			parsedBundle.PrivateKeyType = certutil.ECPrivateKey
			parsedBundle.PrivateKeyBytes = pemBlock.Bytes
			parsedBundle.PrivateKey = signer

		} else if signer, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err == nil {
			if parsedBundle.PrivateKeyType != certutil.UnknownPrivateKey {
				return nil, errutil.UserError{Err: "more than one private key given; provide only one private key in the bundle"}
			}
			parsedBundle.PrivateKeyType = certutil.RSAPrivateKey
			parsedBundle.PrivateKeyFormat = certutil.PKCS1Block
			parsedBundle.PrivateKeyBytes = pemBlock.Bytes
			parsedBundle.PrivateKey = signer
		} else if signer, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes); err == nil {
			parsedBundle.PrivateKeyFormat = certutil.PKCS8Block

			if parsedBundle.PrivateKeyType != certutil.UnknownPrivateKey {
				return nil, errutil.UserError{Err: "More than one private key given; provide only one private key in the bundle"}
			}
			switch signer := signer.(type) {
			case *rsa.PrivateKey:
				parsedBundle.PrivateKey = signer
				parsedBundle.PrivateKeyType = certutil.RSAPrivateKey
				parsedBundle.PrivateKeyBytes = pemBlock.Bytes
			case *ecdsa.PrivateKey:
				parsedBundle.PrivateKey = signer
				parsedBundle.PrivateKeyType = certutil.ECPrivateKey
				parsedBundle.PrivateKeyBytes = pemBlock.Bytes
			}
		} else if certificates, err := x509.ParseCertificates(pemBlock.Bytes); err == nil {
			certPath = append(certPath, &certutil.CertBlock{
				Certificate: certificates[0],
				Bytes:       pemBlock.Bytes,
			})
		} else if x509.IsEncryptedPEMBlock(pemBlock) {
			return nil, errutil.UserError{Err: "Encrypted private key given; provide only decrypted private key in the bundle"}
		}
	}

	for _, certBlock := range certPath {
		if certBlock.Certificate.IsCA {
			parsedBundle.CAChain = append(parsedBundle.CAChain, certBlock)
			continue
		}
		if parsedBundle.Certificate != nil {
			// Only one certificate can be set
			return nil, errutil.UserError{Err: "more than one certificate given; provide only one non-CA certificate in the bundle"}
		}
		parsedBundle.Certificate = certBlock.Certificate
		parsedBundle.CertificateBytes = certBlock.Bytes
	}

	if err := parsedBundle.Verify(); err != nil {
		return nil, errutil.UserError{Err: fmt.Sprintf("verification of parsed bundle failed: %s", err)}
	}

	return parsedBundle, nil
}
