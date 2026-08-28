package crypto

const saltSize = 16

type SignedFile struct {
	Filename  string
	Content   []byte
	Signature []byte
}
