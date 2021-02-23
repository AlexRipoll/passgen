package main

import (
	"fmt"
	"github.com/AlexRipoll/passgen/passgen"
	"os"
)

func main()  {
	password, err := passgen.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(password)
}
