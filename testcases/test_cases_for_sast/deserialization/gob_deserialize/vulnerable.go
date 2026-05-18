import "encoding/gob"
dec := gob.NewDecoder(r)
var m map[string]interface{}
dec.Decode(&m)
