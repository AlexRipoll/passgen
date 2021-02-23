package passgen

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"strings"
)

var (
	schemes = map[string]string{
		"hexadecimal": "0123456789abcdef",
		"base32":      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		"base58":      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789",
		"base64":      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	}
)

var (
	ErrInvalidEncodingScheme = errors.New("invalid encoding scheme provided")
	ErrInvalidLength         = errors.New("password length must be at greater than 0")
)

type Password struct {
	Scheme  Scheme
	Length  int
	Entropy int
}

type Scheme struct {
	Name       string
	Characters string
}

func New() (string, error) {
	var p Password
	flag.StringVar(&p.Scheme.Name, "s", "base64", "the encoding scheme to use for generating the password")
	flag.IntVar(&p.Length, "n", 8, "the number of characters to have in the password")

	flag.Parse()

	if err := p.schemeValidation(); err != nil {
		return "", err
	}

	if p.Length <= 0 {
		return "", ErrInvalidLength
	}
	pass, err := generate(p.Scheme, p.Length)
	if err != nil {
		return "", err
	}
	return pass, nil
}

func (p *Password) schemeValidation() error {
	schemeName := strings.ToLower(p.Scheme.Name)

	switch  schemeName{
	case "hexadecimal", "base32", "base58", "base64":
		p.Scheme.Characters = schemes[schemeName]
		return nil
	default:
		return ErrInvalidEncodingScheme
	}
}

func generate(scheme Scheme, length int) (string, error) {

	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return "", err
	}
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(scheme.Characters))))
		if err != nil {
			return "", err
		}

		b[i] = scheme.Characters[num.Int64()]
	}

	return string(b), nil
}
