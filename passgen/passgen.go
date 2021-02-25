package passgen

import (
	"crypto/rand"
	"errors"
	"flag"
	"math/big"
	"strings"
)

// TODO add goroutines for selecting characters more efficiently

var (
	schemes = map[string]string{
		"hexadecimal": "0123456789abcdef",
		"base32":      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		"base58":      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789",
		"base64":      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	}

	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	special = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

var (
	ErrInvalidEncodingScheme = errors.New("invalid encoding scheme provided")
	ErrInvalidLength         = errors.New("password length must be at greater than 0")
)

type Password struct {
	Scheme       Scheme
	Length       int
	Capitals     int
	Digits       int
	SpecialChars int
	Entropy      int
}

type Scheme struct {
	Name       string
	Characters string
}

type Custom struct {
	Amount int
}

func New() (string, error) {
	var p Password
	flag.StringVar(&p.Scheme.Name, "s", "base64", "the encoding scheme to use for generating the password")
	flag.IntVar(&p.Length, "l", 8, "the desired password length")
	flag.IntVar(&p.Capitals, "C", 0, "the desired number of upper-case letters in the password")
	flag.IntVar(&p.Digits, "N", 0, "the desired number of digits in the password")
	flag.IntVar(&p.SpecialChars, "S", 0, "the desired number of special characters in the password")

	flag.Parse()

	if err := p.schemeValidation(); err != nil {
		return "", err
	}

	if p.Length <= 0 {
		return "", ErrInvalidLength
	}

	var pass string
	var err error
	// if none of the specific flags are set then generate a totally random password.
	// TODO change to subcommands
	if p.Capitals == 0 && p.Digits == 0 && p.SpecialChars == 0 {
		pass, err = generate(p.Scheme, p.Length)
		if err != nil {
			return "", err
		}
	}else {
		pass, err = generateCustom(p.Length, p.Capitals, p.Digits, p.SpecialChars)
		if err != nil {
			return "", err
		}
	}

	return pass, nil
}

func (p *Password) schemeValidation() error {
	schemeName := strings.ToLower(p.Scheme.Name)

	switch schemeName {
	case "hexadecimal", "base32", "base58", "base64":
		p.Scheme.Characters = schemes[schemeName]
		return nil
	default:
		return ErrInvalidEncodingScheme
	}
}

func generate(scheme Scheme, length int) (string, error) {

	b, err := selector(scheme.Characters, length)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func generateCustom(length, caps, nums, speChars int) (string, error) {

	requirementLength := caps + nums + speChars

	passLength := max(length, requirementLength)
	chars := make([]byte, passLength-1)

	if caps > 0 {
		res, err := selector(upper, caps)
		if err != nil {
			return "", err
		}
		chars = append(chars, res...)
	}
	if nums > 0 {
		res, err := selector(digits, nums)
		if err != nil {
			return "", err
		}
		chars = append(chars, res...)
	}
	if speChars > 0 {
		res, err := selector(special, speChars)
		if err != nil {
			return "", err
		}
		chars = append(chars, res...)
	}
	if length > requirementLength {
		remain := length - requirementLength
		res, err := selector(lower, remain)
		if err != nil {
			return "", err
		}
		chars = append(chars, res...)
	}

	// TODO move to func
	mix := make([]byte, len(chars))
	it := len(chars) - 1
	for i := 0; i < it; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		mix[i] = chars[num.Int64()]
		chars[num.Int64()] = chars[len(chars) - 1]
		chars[len(chars) -1 ] = 0
		chars = chars[:len(chars) -1]
	}
	mix[len(mix) - 1] = chars[0]

	return string(mix), nil
}

func selector(alphabet string, amount int) ([]byte, error) {
	b := make([]byte, amount)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	for i := 0; i < amount; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return nil, err
		}

		b[i] = alphabet[num.Int64()]
	}
	return b, nil
}

func max(input1, input2 int) int {
	if input1 > input2 {
		return input1
	}
	return input2
}
