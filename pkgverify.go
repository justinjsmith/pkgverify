package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"go/scanner"
	"io"
	"io/ioutil"
	"math"
	"os"
	"time"
)

const filechunk = 8192

const (
	certPEMBlockType = "BEGIN CERTIFICATE"
)

var (
	file        = flag.String("f", "", "the file to verify")
	certificate = flag.String("c", "", "the certificate to use for signature verification")
	url         = flag.String("u", "", "the URL to check for obtaining the certificate")
	exitCode    = 0
)

type Manifest struct {
	Company     string `json:",omitempty"`
	Product     string `json:",omitempty"`
	PackageName string
	PackageSha1 string // use string so value easy to compare with shasum output
	ReleaseDate time.Time
	Signature   []byte `json:",omitempty"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "\nusage: pkgverify -f [path] -c [path]\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(2)
}

func report(err error) {
	scanner.PrintError(os.Stderr, err)
	exitCode = 2
}

func main() {
	pkgVerifyMain()
	os.Exit(exitCode)
}

func pkgVerifyMain() {
	flag.Usage = usage
	flag.Parse()

	if *file == "" {
		usage()
	}
	if *certificate == "" && *url == "" {
		usage()
	}

	// open the file to verify and calculate the file's Sha1
	fileToVerify, err := os.Open(*file)
	if err != nil {
		report(err)
		return
	}
	defer fileToVerify.Close()
	pkgSha1 := calcSha(fileToVerify)

	// open and unmarshal the manifest
	manifestToVerifyBytes, err := ioutil.ReadFile(*file + ".manifest")
	if err != nil {
		report(err)
		return
	}
	var manifestToVerify Manifest
	err = json.Unmarshal(manifestToVerifyBytes, &manifestToVerify)
	if err != nil {
		report(err)
		return
	}

	// verify the SHA1s match
	if fmt.Sprintf("%x", pkgSha1) != manifestToVerify.PackageSha1 {
		report(fmt.Errorf("SHAs don't match: %x and %s", pkgSha1, manifestToVerify.PackageSha1))
		return
	}

	// open the certificate file and parse it (from a file to start with)
	certBytes, err := ioutil.ReadFile(*certificate)
	if err != nil {
		report(err)
		return
	}
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		report(fmt.Errorf("No PEM block found"))
		return
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		report(err)
		return
	}
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		report(fmt.Errorf("Not an RSA public key"))
		return
	}

	// hold the signature from the manifest
	manSig := make([]byte, len(manifestToVerify.Signature))
	copy(manSig, manifestToVerify.Signature)

	// clear the manifest signature
	manifestToVerify.Signature = nil

	// marshal the manifest without the signature
	manifestNoSig, err := json.Marshal(manifestToVerify)
	if err != nil {
		report(err)
		return
	}

	// calculate the SHA1 of the manifest
	manifestSha1 := sha1.New()
	manifestSha1.Write(manifestNoSig)
	manShaVal := manifestSha1.Sum(nil)

	var h crypto.Hash
	err = rsa.VerifyPKCS1v15(rsaPub, h, manShaVal, manSig)
	if err != nil {
		report(err)
		return
	}

	fmt.Println("Success!")
	fmt.Printf("File %s verified against %s\n", fileToVerify.Name(),
		fileToVerify.Name()+".manifest")

}

func calcSha(fileToVerify *os.File) []byte {
	info, _ := fileToVerify.Stat()
	filesize := info.Size()
	blocks := uint64(math.Ceil(float64(filesize) / float64(filechunk)))
	hash := sha1.New()
	for i := uint64(0); i < blocks; i++ {
		blocksize := int(math.Min(filechunk, float64(filesize-int64(i*filechunk))))
		buf := make([]byte, blocksize)
		fileToVerify.Read(buf)
		io.WriteString(hash, string(buf))
	}
	return hash.Sum(nil)
}
