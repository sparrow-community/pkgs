package auth

import (
	"crypto/rsa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"time"
)

type JwkType int

const (
	JwkTypeJson JwkType = iota + 1
	JwkTypePem
)

// Options .
type Options struct {
	defaultRsaKeyPair  bool
	rsaPrivateKey      *rsa.PrivateKey
	rsaPublicKey       *rsa.PublicKey
	rsaPrivateKeyBytes []byte
	RsaPublicKeyBytes  []byte
	jwkSet             jwk.Set
	jwkData            []byte
	jwkType            JwkType
}

type Option func(*Options)

func WithDefaultRsaKeyPair(b bool) Option {
	return func(options *Options) {
		options.defaultRsaKeyPair = b
	}
}

func WithRsaPrivateKey(key *rsa.PrivateKey) Option {
	return func(options *Options) {
		options.rsaPrivateKey = key
	}
}

func WithRsaPublic(key *rsa.PublicKey) Option {
	return func(options *Options) {
		options.rsaPublicKey = key
	}
}

func WithRsaPrivateKeyBytes(privateKeyBytes []byte) Option {
	return func(options *Options) {
		options.rsaPrivateKeyBytes = privateKeyBytes
	}
}

func WithRsaPublicKeyBytes(publicKeyBytes []byte) Option {
	return func(options *Options) {
		options.RsaPublicKeyBytes = publicKeyBytes
	}
}

func WithJwk(data []byte, jwkType JwkType) Option {
	return func(options *Options) {
		options.jwkData = data
		options.jwkType = jwkType
	}
}

// TokenOptions .
type TokenOptions struct {
	subject    string
	issuer     string
	expiration time.Duration
	Claims     map[string]any
}

type TokenOption func(options *TokenOptions)

func NewGenerateTokenOptions(opts ...TokenOption) TokenOptions {
	var options TokenOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

func WithSubject(sub string) TokenOption {
	return func(options *TokenOptions) {
		options.subject = sub
	}
}

func WithIssuer(issuer string) TokenOption {
	return func(options *TokenOptions) {
		options.issuer = issuer
	}
}

func WithExpiration(expiration time.Duration) TokenOption {
	return func(options *TokenOptions) {
		options.expiration = expiration
	}
}

func WithClaims(claims map[string]any) TokenOption {
	return func(options *TokenOptions) {
		options.Claims = claims
	}
}
