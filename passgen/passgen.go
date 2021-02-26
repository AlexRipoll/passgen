package passgen

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
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
	wg    = &sync.WaitGroup{}
	mutex = &sync.Mutex{}
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

type Form struct {
	Alphabet string
	Amount   int
}

func New() (string, error) {
	start := time.Now()
	var p Password

	flag.IntVar(&p.Length, "l", 8, "the desired password length")

	scheme := flag.NewFlagSet("scheme", flag.ExitOnError)
	scheme.IntVar(&p.Length, "l", 8, "the desired password length")
	scheme.StringVar(&p.Scheme.Name, "s", "base64", "the encoding scheme to use for generating the password")

	form := flag.NewFlagSet("form", flag.ExitOnError)
	form.IntVar(&p.Length, "l", 8, "the desired password length")
	form.IntVar(&p.Capitals, "C", 0, "the desired number of upper-case letters in the password")
	form.IntVar(&p.Digits, "D", 0, "the desired number of digits in the password")
	form.IntVar(&p.SpecialChars, "S", 0, "the desired number of special characters in the password")

	var pass string
	var err error

	switch os.Args[1] {
	case "form":
		form.Parse(os.Args[2:])
		if p.Length <= 0 {
			return "", ErrInvalidLength
		}
		pass, err = generateCustom(p.Length, p.Capitals, p.Digits, p.SpecialChars)
		if err != nil {
			break
		}
	case "scheme":
		scheme.Parse(os.Args[2:])
		if p.Length <= 0 {
			return "", ErrInvalidLength
		}
		if err = p.schemeValidation(); err != nil {
			break
		}
		pass, err = generate(p.Scheme, p.Length)
		if err != nil {
			break
		}
	default:
		fmt.Println("unknown subcommand")
		os.Exit(1)
	}

	elapsed := time.Since(start)
	fmt.Println(elapsed)
	return pass, err
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

	var chars []byte
	forms := []Form{{upper, caps}, {digits, nums}, {special, speChars}}
	for _, v := range forms {
		wg.Add(1)
		go func(form Form) error {
			if form.Amount > 0 {
				res, err := selector(form.Alphabet, form.Amount)
				if err != nil {
					return err
				}
				mutex.Lock()
				chars = append(chars, res...)
				mutex.Unlock()
			}
			wg.Done()
			return nil
		}(v)
	}
	wg.Add(1)
	go func() error {
		if length > requirementLength {
			remain := length - requirementLength
			res, err := selector(lower, remain)
			if err != nil {
				return err
			}
			mutex.Lock()
			chars = append(chars, res...)
			mutex.Unlock()
		}
		wg.Done()
		return nil
	}()

	wg.Wait()
	mix, err := mixer(chars)
	if err != nil {
		return "", err
	}

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

func mixer(stack []byte) ([]byte, error) {
	mix := make([]byte, len(stack))
	it := len(stack) - 1
	for i := 0; i < it; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(stack))))
		if err != nil {
			return nil, err
		}
		mix[i] = stack[num.Int64()]
		stack[num.Int64()] = stack[len(stack)-1]
		stack[len(stack)-1] = 0
		stack = stack[:len(stack)-1]
	}
	mix[len(mix)-1] = stack[0]

	return mix, nil
}

func max(input1, input2 int) int {
	if input1 > input2 {
		return input1
	}
	return input2
}
