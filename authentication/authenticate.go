package authentication

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"time"
)

type Token struct {
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	Exp          time.Time              `json:"exp,omitempty"`
	Iat          time.Time              `json:"iat,omitempty"`
	Iss          string                 `json:"iss,omitempty"`
	Subject      string                 `json:"subject"`
	Claims       map[string]interface{} `json:"claims"`
}

type Authenticate struct {
	opts Options
}

func New(opt ...Option) (*Authenticate, error) {
	opts := Options{}
	for _, o := range opt {
		o(&opts)
	}

	if opts.defaultRsaKeyPair {
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil, err
		}
		if err := privateKey.Validate(); err != nil {
			return nil, err
		}
		publicKey := privateKey.Public()
		opts.rsaPrivateKey = privateKey
		opts.rsaPublicKey = publicKey.(*rsa.PublicKey)
	}

	if len(opts.rsaPrivateKeyBytes) > 0 {
		p, _ := pem.Decode(opts.rsaPrivateKeyBytes)
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		opts.rsaPrivateKey = rsaPrivateKey
	}

	if len(opts.RsaPublicKeyBytes) > 0 {
		p, _ := pem.Decode(opts.RsaPublicKeyBytes)
		rsaPublicKey, err := x509.ParsePKCS1PublicKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		opts.rsaPublicKey = rsaPublicKey
	}

	if len(opts.jwkData) > 0 && opts.jwkType == JwkTypeJson {
		set, err := jwk.ParseString(string(opts.jwkData))
		if err != nil {
			return nil, err
		}
		opts.jwkSet = set
	}

	return &Authenticate{opts: opts}, nil
}

func (a *Authenticate) Generate(opts ...TokenOption) (*Token, error) {
	tokenOpts := NewGenerateTokenOptions(opts...)
	b := jwt.NewBuilder().
		Subject(tokenOpts.subject).
		Issuer(tokenOpts.issuer).
		IssuedAt(time.Now())

	for k, v := range tokenOpts.Claims {
		b.Claim(k, v)
	}

	accessToken, err := b.
		Expiration(time.Now().Add(tokenOpts.expiration)).
		Build()
	if err != nil {
		return nil, err
	}
	signAccessToken, err := jwt.Sign(accessToken, jwt.WithKey(jwa.RS256, a.opts.rsaPrivateKey))
	if err != nil {
		return nil, err
	}

	refreshToken, err := b.
		Expiration(time.Now().Add(tokenOpts.expiration + 24*time.Hour)).
		Build()
	if err != nil {
		return nil, err
	}
	signRefreshToken, err := jwt.Sign(refreshToken, jwt.WithKey(jwa.RS256, a.opts.rsaPrivateKey))
	if err != nil {
		return nil, err
	}
	return &Token{
		AccessToken:  string(signAccessToken),
		RefreshToken: string(signRefreshToken),
		Exp:          accessToken.Expiration(),
		Iat:          accessToken.IssuedAt(),
		Iss:          accessToken.Issuer(),
	}, nil
}

func (a *Authenticate) Parse(signedToken []byte) (*Token, error) {
	token, err := jwt.Parse(signedToken, jwt.WithKey(jwa.RS256, a.opts.rsaPublicKey), jwt.WithValidate(false))
	if err != nil {
		return nil, err
	}
	return &Token{
		Subject: token.Subject(),
		Claims:  token.PrivateClaims(),
		Exp:     token.Expiration(),
		Iat:     token.IssuedAt(),
		Iss:     token.Issuer(),
	}, nil
}

func (a *Authenticate) Inspect(signedToken []byte) (*Token, error) {
	token, err := jwt.Parse(signedToken, jwt.WithKey(jwa.RS256, a.opts.rsaPublicKey))
	if err != nil {
		return nil, err
	}
	return &Token{
		Subject: token.Subject(),
		Claims:  token.PrivateClaims(),
	}, nil
}

func (a *Authenticate) InspectWithJwk(signedToken []byte) (*Token, error) {
	token, err := jwt.Parse(signedToken, jwt.WithKeySet(a.opts.jwkSet, jws.WithUseDefault(true)))
	if err != nil {
		return nil, err
	}
	return &Token{
		Subject: token.Subject(),
		Claims:  token.PrivateClaims(),
	}, nil
}

func (a *Authenticate) Jwks() ([]byte, error) {
	set := jwk.NewSet()
	key, err := jwk.FromRaw(a.opts.rsaPublicKey)
	if err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}
	if err := set.AddKey(key); err != nil {
		return nil, err
	}
	return json.Marshal(set)
}

func (a *Authenticate) PrivateKeyBytes() []byte {
	prvEncodeBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(a.opts.rsaPrivateKey),
	})
	return prvEncodeBytes
}

func (a *Authenticate) PublicKeyBytes() []byte {
	pubEncodeBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PublicKey(a.opts.rsaPublicKey),
	})
	return pubEncodeBytes
}
