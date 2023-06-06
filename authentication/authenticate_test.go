package authentication

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"testing"
	"time"
)

func TestGenerateAndInspectWithKey(t *testing.T) {
	privateKey := generateRsaKey()
	authenticate, err := New(
		WithRsaPrivateKey(privateKey),
		WithRsaPublic(&privateKey.PublicKey),
	)

	if err != nil {
		t.Error(err)
	}

	ret, err := authenticate.Generate(
		WithSubject("uid"),
		WithIssuer("github.com/sparrow-community"),
		WithExpiration(time.Hour),
		WithClaims(map[string]any{
			"kid":    "sparrow-community",
			"scopes": []string{"user", "admin"},
		}),
	)
	t.Log(ret)
	if err != nil {
		t.Error(err)
	}
	accessTokenUser, err := authenticate.Inspect([]byte(ret.AccessToken))
	if err != nil {
		t.Error(err)
	}
	t.Logf("%+#v", accessTokenUser)
	refreshTokenUser, err := authenticate.Inspect([]byte(ret.RefreshToken))
	if err != nil {
		t.Error(err)
	}
	t.Logf("%+#v", refreshTokenUser)
}

// use jwk inspect token
func TestJWKs(t *testing.T) {
	// generate token
	rsaPrivateBytes, err := os.ReadFile("test/id_rsa_test")
	if err != nil {
		t.Error(err)
	}
	rsaPublicBytes, err := os.ReadFile("test/id_rsa_test.pub")
	if err != nil {
		t.Error(err)
	}

	authenticate, err := New(
		WithRsaPrivateKeyBytes(rsaPrivateBytes),
		WithRsaPublicKeyBytes(rsaPublicBytes),
	)

	if err != nil {
		t.Error(err)
	}

	ret, err := authenticate.Generate(
		WithSubject("uid"),
		WithIssuer("github.com/sparrow-community"),
		WithExpiration(time.Hour),
		WithClaims(map[string]any{
			"kid":    "sparrow-community",
			"scopes": []string{"user", "admin"},
		}),
	)
	t.Logf("%+#v", ret)
	if err != nil {
		t.Error(err)
	}
	jwkJson, err := authenticate.Jwks()
	if err != nil {
		t.Error(err)
	}
	t.Log(string(jwkJson))

	// use jwk inspect token
	clientAuthenticate, err := New(
		WithJwk(jwkJson, JwkTypeJson),
	)
	accessTokenUser, err := clientAuthenticate.InspectWithJwk([]byte(ret.AccessToken))
	if err != nil {
		t.Error(err)
	}
	t.Logf("%+#v", accessTokenUser)
}

func TestGenerateAndInspectWithKeyFile(t *testing.T) {
	rsaPrivateBytes, err := os.ReadFile("test/id_rsa_test")
	if err != nil {
		t.Error(err)
	}
	rsaPublicBytes, err := os.ReadFile("test/id_rsa_test.pub")
	if err != nil {
		t.Error(err)
	}

	authenticate, err := New(
		WithRsaPrivateKeyBytes(rsaPrivateBytes),
		WithRsaPublicKeyBytes(rsaPublicBytes),
	)

	if err != nil {
		t.Error(err)
	}

	ret, err := authenticate.Generate(
		WithSubject("uid"),
		WithIssuer("github.com/sparrow-community"),
		WithExpiration(time.Hour),
		WithClaims(map[string]any{
			"kid":    "sparrow-community",
			"scopes": []string{"user", "admin"},
		}),
	)
	t.Log(ret)
	if err != nil {
		t.Error(err)
	}
	accessTokenUser, err := authenticate.Inspect([]byte(ret.AccessToken))
	if err != nil {
		t.Error(err)
	}
	t.Logf("%+#v", accessTokenUser)
	refreshTokenUser, err := authenticate.Inspect([]byte(ret.RefreshToken))
	if err != nil {
		t.Error(err)
	}
	t.Logf("%+#v", refreshTokenUser)
}

// Generate rsa key pair to file
func TestGenerateRsaKeyPairToFile(t *testing.T) {
	privateKey := generateRsaKey()
	prvEncodeBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	})

	if err := os.WriteFile("test/id_rsa_test", prvEncodeBytes, 0644); err != nil {
		t.Error(err)
	}

	publicKey := privateKey.Public()
	pubEncodeBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PublicKey(publicKey.(*rsa.PublicKey)),
	})

	if err := os.WriteFile("test/id_rsa_test.pub", pubEncodeBytes, 0644); err != nil {
		t.Error(err)
	}

}

// Generate an RSA key pair
func generateRsaKey() *rsa.PrivateKey {
	bitSize := 4096
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	if err := privateKey.Validate(); err != nil {
		log.Fatal(err)
	}

	return privateKey
}
