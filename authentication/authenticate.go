package authentication

import (
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
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Exp          time.Time `json:"exp,omitempty"`
	Iat          time.Time `json:"iat,omitempty"`
	Iss          string    `json:"iss,omitempty"`
}

type User struct {
	ID       string                 `json:"id"`
	Metadata map[string]interface{} `json:"metadata"`
}

type Authenticate struct {
	opts Options
}

func New(opt ...Option) (*Authenticate, error) {
	opts := Options{}
	for _, o := range opt {
		o(&opts)
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

	for k, v := range tokenOpts.Metadata {
		b.Claim(k, v)
	}

	accessToken, err := b.
		Expiration(tokenOpts.expiration).
		Build()
	if err != nil {
		return nil, err
	}
	signAccessToken, err := jwt.Sign(accessToken, jwt.WithKey(jwa.RS256, a.opts.rsaPrivateKey))
	if err != nil {
		return nil, err
	}

	refreshToken, err := b.
		Expiration(tokenOpts.expiration.Add(time.Hour)).
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

func (a *Authenticate) Inspect(signedToken []byte) (*User, error) {
	token, err := jwt.Parse(signedToken, jwt.WithKey(jwa.RS256, a.opts.rsaPublicKey))
	if err != nil {
		return nil, err
	}
	return &User{
		ID:       token.Subject(),
		Metadata: token.PrivateClaims(),
	}, nil
}

func (a *Authenticate) InspectWithJwk(signedToken []byte) (*User, error) {
	token, err := jwt.Parse(signedToken, jwt.WithKeySet(a.opts.jwkSet, jws.WithUseDefault(true)))
	if err != nil {
		return nil, err
	}
	return &User{
		ID:       token.Subject(),
		Metadata: token.PrivateClaims(),
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
