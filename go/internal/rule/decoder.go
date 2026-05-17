package rule

import (
	"bytes"
	"encoding/json"
)

type jsonDec struct{ d *json.Decoder }

func newDecoder(raw []byte) *jsonDec {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return &jsonDec{d: d}
}

func (j *jsonDec) Decode(v *any) error { return j.d.Decode(v) }
