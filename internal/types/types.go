package types

type KeyRecoveryJson struct {
	K1Encr string `json:"k1"`
	K3     string `json:"k3"`
	S      string `json:"s"`
}

type KeyRecoveryData struct {
	K1Encr, K3, S []byte
}
