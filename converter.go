package gowt

import (
	"encoding/base64"
	"math/big"
)

type converter interface {
	base64ToBigInt(encoded string) (*big.Int, error)
}

type stdConverter struct{}

func (c *stdConverter) base64ToBigInt(encoded string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(decoded), nil
}

func NewConverter() converter {
	return &stdConverter{}
}
