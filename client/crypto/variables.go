package crypto

const saltSize = 16

// SignedFile represents a file with its content and signature.
// a .signed file is composed as follows:
//
//	[4 byte]   Magic       "SIGN"
//	[2 byte]   Filename length
//	[N byte]   Filename
//	[8 byte]   File size
//	[N byte]   File content
//	[2 byte]   Signature length
//	[N byte]   Signature
type SignedFile struct {
	Filename  string
	Content   []byte
	Signature []byte
}
