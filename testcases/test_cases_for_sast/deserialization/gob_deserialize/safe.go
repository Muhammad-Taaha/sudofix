import "encoding/json"
dec := json.NewDecoder(r)
var m map[string]interface{}
dec.Decode(&m)
