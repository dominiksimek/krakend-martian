package martian

import (
  "bytes"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "strings"

  "github.com/google/martian/parse"
)

func init() {
  parse.Register("fromJWT.Modifier", modifierFromJSON)
}

type modifierEntry struct {
  Name   string `json:"name"`
  KeyJWT string `json:"keyJWT"`
}

// FromJWT implements martian.RequestModifier interface. It writes value from JWT to the request's query, path and
// body (only JSON body is supported).
type FromJWT struct {
  Querystring []modifierEntry      `json:"querystring"`
  Path        []modifierEntry      `json:"path"`
  JsonBody    []modifierEntry      `json:"jsonBody"`
  //FormBody    []modifierEntry      `json:"formBody"`
  Scope       []parse.ModifierType `json:"scope"`
  jwt         map[string]interface{}
}

// NewModifier creates new FromJWT object (constructor).
func NewModifier() *FromJWT {
  return &FromJWT{}
}

// ModifyRequest modifies request.
func (self *FromJWT) ModifyRequest(req *http.Request) error {
  jwt, err := self.parseJWT(req)
  if err != nil {
    return err
  }
  fmt.Printf("jwt.payload: %v\n", jwt)
  // modify query params
  query := req.URL.Query()
  for _, entry := range self.Querystring {
    newVal, ok := jwt[entry.KeyJWT]
    if !ok {
      return fmt.Errorf("key=%v not in jwt", entry.KeyJWT)
    }
    query.Set(entry.Name, fmt.Sprintf("%v", newVal))
    // if there are more parameters with same name (e.g. ?key1=10&key1=20&key1=30), query.Set rewrites this array by
    // one value; so if we want to preserve array of values, we should use query.Set & query.Add (for each query value)
  }
  req.URL.RawQuery = query.Encode()

  // modify path (replace some strings)
  for _, entry := range self.Path {
    newVal, ok := jwt[entry.KeyJWT]
    if !ok {
      return fmt.Errorf("key=%v not in jwt", entry.KeyJWT)
    }
    req.URL.Path = strings.ReplaceAll(req.URL.Path, entry.Name, fmt.Sprintf("%v", newVal))
  }

  // modify json body (replace some keys)
  if req.Body == nil || len(self.JsonBody) == 0 {
    return nil
  }
  bodyBytes, err := ioutil.ReadAll(req.Body)
  if err != nil {
    return err
  }
  req.Body.Close()

  bodyData := make(map[string]interface{})
  if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
    return err
  }

  for _, entry := range self.JsonBody {
    newVal, ok := jwt[entry.KeyJWT]
    if !ok {
      return fmt.Errorf("key=%v not in jwt", entry.KeyJWT)
    }
    bodyData[entry.Name] = newVal
  }
  newBodyBytes, err := json.Marshal(bodyData)
  if err != nil {
    return err
  }
  req.Body = ioutil.NopCloser(bytes.NewBuffer(newBodyBytes))

  // results
  //fmt.Printf("req.URL: %v\n", req.URL.String())
  //fmt.Printf("req.Body: %v\n", req.Body)
  return nil
}

// modifierFromJSON creates modifier from JSON data.
func modifierFromJSON(b []byte) (*parse.Result, error) {
  modifier := FromJWT{}
  if err := json.Unmarshal(b, &modifier); err != nil {
    return nil, err
  }
  return parse.NewResult(&modifier, modifier.Scope)
}

// parseJWT parses JWT from "Authorization" header.
func (self *FromJWT) parseJWT(req *http.Request) (map[string]interface{}, error) {
  var jwtData map[string]interface{}
  auth := req.Header.Get("Authorization")
  if !strings.HasPrefix(auth, "Bearer ") {
    return nil, fmt.Errorf("not \"Bearer\" prefix")
  }
  jwt := auth[len("Bearer "):]
  jwtParts := strings.Split(jwt, ".")
  if len(jwtParts) < 3 {
    return nil, fmt.Errorf("bad format of jwt")
  }
  b, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
  if err != nil {
    return nil, err
  }
  if err := json.Unmarshal(b, &jwtData); err != nil {
      return nil, err
  }
  return jwtData, nil
}
