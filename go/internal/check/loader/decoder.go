package loader

import (
	"bytes"
	"encoding/json"
)

type jsonDecoder struct{ d *json.Decoder }

func newDecoder(raw []byte) *jsonDecoder {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return &jsonDecoder{d: d}
}

func (j *jsonDecoder) Decode(v *any) error {
	return j.d.Decode(v)
}
