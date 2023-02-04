// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package types

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

var _ = (*elgamalPublicKeyMarshaling)(nil)

// MarshalJSON marshals as JSON.
func (e ElgamalPublicKey) MarshalJSON() ([]byte, error) {
	type ElgamalPublicKey struct {
		P hexutil.Bytes `json:"p"     gencodec:"required"`
		G hexutil.Bytes `json:"g"     gencodec:"required"`
		Y hexutil.Bytes `json:"y"     gencodec:"required"`
	}
	var enc ElgamalPublicKey
	enc.P = e.P
	enc.G = e.G
	enc.Y = e.Y
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (e *ElgamalPublicKey) UnmarshalJSON(input []byte) error {
	type ElgamalPublicKey struct {
		P *hexutil.Bytes `json:"p"     gencodec:"required"`
		G *hexutil.Bytes `json:"g"     gencodec:"required"`
		Y *hexutil.Bytes `json:"y"     gencodec:"required"`
	}
	var dec ElgamalPublicKey
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.P == nil {
		return errors.New("missing required field 'p' for ElgamalPublicKey")
	}
	e.P = *dec.P
	if dec.G == nil {
		return errors.New("missing required field 'g' for ElgamalPublicKey")
	}
	e.G = *dec.G
	if dec.Y == nil {
		return errors.New("missing required field 'y' for ElgamalPublicKey")
	}
	e.Y = *dec.Y
	return nil
}
