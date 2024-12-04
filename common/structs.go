package common

type TPMAttestation struct {
	TPMVersion int    `json:"TPMVersion"`
	Public     string `json:"Public"`
	Quotes     []struct {
		Version   int    `json:"Version"`
		Quote     string `json:"Quote"`
		Signature string `json:"Signature"`
	} `json:"Quotes"`
	PCRs []struct {
		Index     int    `json:"Index"`
		Digest    string `json:"Digest"`
		DigestAlg int    `json:"DigestAlg"`
	} `json:"PCRs"`
	EventLog string `json:"EventLog"`
}
