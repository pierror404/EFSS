package crypto

const saltSize = 16

// SignedFile represents a file with its content and signature.
type SignedFile struct {
	Filename  string
	Content   []byte
	Signature []byte
}
