package random

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func SecureString(n int) (string, error) {
	if n < 1 {
		return "", fmt.Errorf("string length must be > 0")
	}

	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, n)

	for i := range bytes {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}

		bytes[i] = chars[num.Int64()]
	}

	return string(bytes), nil
}
