package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  encrypt -in <infile> -out <outfile> -key <16-byte string>|-hexkey <32hex>\n")
	fmt.Fprintf(os.Stderr, "  decrypt -in <infile> -out <outfile> -key <16-byte string>|-hexkey <32hex>\n")
	os.Exit(2)
}

func parseKey(fs *flag.FlagSet) []byte {
	k := fs.Lookup("key").Value.String()
	h := fs.Lookup("hexkey").Value.String()
	if k != "" && h != "" {
		fmt.Fprintln(os.Stderr, "specify only one of -key or -hexkey")
		os.Exit(2)
	}
	if k == "" && h == "" {
		fmt.Fprintln(os.Stderr, "key required")
		os.Exit(2)
	}
	if k != "" {
		if len(k) != 16 {
			fmt.Fprintln(os.Stderr, "key string must be exactly 16 bytes for AES-128")
			os.Exit(2)
		}
		return []byte(k)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad hex key: %v\n", err)
		os.Exit(2)
	}
	if len(b) != 16 {
		fmt.Fprintln(os.Stderr, "hex key must decode to 16 bytes")
		os.Exit(2)
	}
	return b
}

func cmdEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	in := fs.String("in", "", "")
	out := fs.String("out", "", "")
	keyStr := fs.String("key", "", "")
	hexKey := fs.String("hexkey", "", "")
	_ = keyStr
	_ = hexKey
	fs.Parse(args)
	if *in == "" || *out == "" {
		usage()
	}
	key := parseKey(fs)
	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *in, err)
		os.Exit(1)
	}
	iv := RandomIV()
	ct, err := CBCEncrypt(data, key, iv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt: %v\n", err)
		os.Exit(1)
	}
	buf := append(iv, ct...)
	if err := os.WriteFile(*out, buf, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("encrypted %s -> %s (%d bytes ciphertext + 16-byte IV prefix)\n", *in, *out, len(ct))
}

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	in := fs.String("in", "", "")
	out := fs.String("out", "", "")
	keyStr := fs.String("key", "", "")
	hexKey := fs.String("hexkey", "", "")
	_ = keyStr
	_ = hexKey
	fs.Parse(args)
	if *in == "" || *out == "" {
		usage()
	}
	key := parseKey(fs)
	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *in, err)
		os.Exit(1)
	}
	if len(data) < 16 {
		fmt.Fprintln(os.Stderr, "ciphertext file too short")
		os.Exit(1)
	}
	iv := data[:16]
	ct := data[16:]
	pt, err := CBCDecrypt(ct, key, iv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, pt, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("decrypted %s -> %s\n", *in, *out)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "encrypt":
		cmdEncrypt(os.Args[2:])
	case "decrypt":
		cmdDecrypt(os.Args[2:])
	default:
		usage()
	}
}
