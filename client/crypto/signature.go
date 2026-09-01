package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

// Sign signs the given data using the provided RSA private key and returns the signature.
func Sign(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)

	signature, err := rsa.SignPSS(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		hash[:],
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)

	if err != nil {
		return nil, err
	}

	return signature, nil
}

// SignFile signs the content of the specified input file
// using the provided RSA private key and writes the signed
// content to the specified output file.
func SignFile(inputFilename string, outputFilename string, privateKey *rsa.PrivateKey) error {

	// file content
	fileContent, err := os.ReadFile(inputFilename)
	if err != nil {
		return err
	}

	// signature
	signature, err := Sign(fileContent, privateKey)
	if err != nil {
		return err
	}

	// create output file
	out, err := os.Create(outputFilename)
	if err != nil {
		return err
	}
	defer out.Close()

	// write the output file
	if err := WriteSignedFile(
		out,
		filepath.Base(inputFilename),
		fileContent,
		signature,
	); err != nil {
		return err
	}

	return nil
}

// WriteSignedFile writes the signed file to the provided writer.
func WriteSignedFile(w io.Writer, filename string, content []byte, signature []byte) error {
	/*
		[4 byte]   Magic       "SIGN"
		[2 byte]   Filename length
		[N byte]   Filename
		[8 byte]   File size
		[N byte]   File content
		[2 byte]   Signature length
		[N byte]   Signature
	*/
	// MAGIC
	if _, err := w.Write([]byte("SIGN")); err != nil {
		return err
	}

	// FILENAME
	filenameBytes := []byte(filename)
	if len(filenameBytes) > math.MaxUint16 {
		return fmt.Errorf("filename troppo lungo")
	}
	if err := binary.Write(
		w,
		binary.BigEndian,
		uint16(len(filenameBytes)),
	); err != nil {
		return err
	}
	if _, err := w.Write(filenameBytes); err != nil {
		return err
	}
	// FILE SIZE
	if err := binary.Write(w, binary.BigEndian, uint64(len(content))); err != nil {
		return err
	}
	// FILE CONTENT
	if _, err := w.Write(content); err != nil {
		return err
	}
	// SIGNATURE SIZE
	if len(signature) > math.MaxUint16 {
		return fmt.Errorf("firma troppo lunga")
	}
	if err := binary.Write(
		w,
		binary.BigEndian,
		uint16(len(signature)),
	); err != nil {
		return err
	}
	// SIGNATURE
	if _, err := w.Write(signature); err != nil {
		return err
	}

	return nil
}

// VerifySignature verifies the signature of the given content using the provided RSA public key.
func VerifySignature(content []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hash := sha256.Sum256(content)

	return rsa.VerifyPSS(
		publicKey,
		crypto.SHA256,
		hash[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
}

// VerifyFile verifies the signature of the signed file specified by the filename using the provided RSA public key.
func VerifyFile(filename string, publicKey *rsa.PublicKey) (*SignedFile, error) {

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	signedFile, err := ReadSignedFile(file)
	if err != nil {
		return nil, err
	}

	err = VerifySignature(signedFile.Content, signedFile.Signature, publicKey)
	if err != nil {
		return signedFile, fmt.Errorf("Invalid signature: %w", err)
	}

	return signedFile, nil
}

// ReadSignedFile reads a signed file from the provided reader and returns a SignedFile struct.
func ReadSignedFile(r io.Reader) (*SignedFile, error) {
	/*
		[4 byte]   Magic       "SIGN"
		[2 byte]   Filename length
		[N byte]   Filename
		[8 byte]   File size
		[N byte]   File content
		[2 byte]   Signature length
		[N byte]   Signature
	*/
	// MAGIC
	magic := make([]byte, 4)

	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}

	if string(magic) != "SIGN" {
		return nil, fmt.Errorf("file non valido")
	}

	// FILENAME LENGTH
	var filenameLen uint16

	if err := binary.Read(
		r,
		binary.BigEndian,
		&filenameLen,
	); err != nil {
		return nil, err
	}

	// FILENAME
	filenameBytes := make([]byte, filenameLen)

	if _, err := io.ReadFull(r, filenameBytes); err != nil {
		return nil, err
	}

	// FILE SIZE
	var fileSize uint64

	if err := binary.Read(
		r,
		binary.BigEndian,
		&fileSize,
	); err != nil {
		return nil, err
	}

	// FILE CONTENT
	content := make([]byte, fileSize)

	if _, err := io.ReadFull(r, content); err != nil {
		return nil, err
	}

	// SIGNATURE LENGTH
	var signatureLen uint16

	if err := binary.Read(
		r,
		binary.BigEndian,
		&signatureLen,
	); err != nil {
		return nil, err
	}

	// SIGNATURE
	signature := make([]byte, signatureLen)

	if _, err := io.ReadFull(r, signature); err != nil {
		return nil, err
	}

	return &SignedFile{
		Filename:  string(filenameBytes),
		Content:   content,
		Signature: signature,
	}, nil
}
