package protocol

import (
	"encoding/json"
)

func (v Version) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name  string `json:"name"`
		Value uint16 `json:"version"`
	}{
		Name:  v.String(),
		Value: uint16(v.Major)<<8 | uint16(v.Minor),
	}
	return json.Marshal(aux)
}
