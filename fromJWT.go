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

type pathPosModifierEntry struct {
  Position int    `json:"position"`
  KeyJWT   string `json:"keyJWT"`
}

type jwt map[string]interface{}

// FromJWT implements martian.RequestModifier interface. It writes value from JWT to the request's query, path and
// body (only JSON body is supported).
// A path can be updated in following ways: 'PathString' entry replaces substring (in path) defined in
// modifierEntry.Name by specified value from JWT; 'PathParam' rewrites path parameter on position defined in
// pathPosModifierEntry.Position by specified value from JWT. Position of some substring in the url means position
// in url split by character "/" indexed from 0. So e.g. substring "{var1}" in url "/some/{var1}/path/{var2}" has
// position 1, substring "{var2}" has position 3 etc.
type FromJWT struct {
  Querystring  []modifierEntry        `json:"querystring"`
  PathString   []modifierEntry        `json:"path_string"`
  PathParam    []pathPosModifierEntry `json:"path_param"`
  JsonBody     []modifierEntry        `json:"json_body"`
  Scope        []parse.ModifierType   `json:"scope"`
  JwtCookieKey string                 `json:"jwt_cookie_key"`
  jwt          jwt
}

// NewModifier creates new FromJWT object (constructor).
func NewModifier() *FromJWT {
  return &FromJWT{}
}

// ModifyRequest modifies request.
func (self *FromJWT) ModifyRequest(req *http.Request) error {
  jwt, err := self.parseJwtValues(req)
  if err != nil {
    return err
  }
  // modify query params
  if err := self.modifyQuerystring(req, jwt); err != nil {
    return err
  }
  // modify path params (set value of path params on specific positions)
  if err := self.modifyPathParams(req, jwt); err != nil {
    return err
  }
  // modify path (replace some strings)
  if err := self.modifyPathStrings(req, jwt); err != nil {
    return err
  }
  // modify json body (replace some keys)
  if err := self.modifyBodyJson(req, jwt); err != nil {
    return err
  }
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

// parseJwtValues parses JWT included in request. A JWT is parsed primary from "Authorization" header. The JWT
// is parsed from Cookie (with name defined in FromJWT.JwtCookieKey) if it's not found in the auth header.
// The function fails if JWT is not present in auth header, nor cookie.
func (self *FromJWT) parseJwtValues(req *http.Request) (jwt, error) {
  var jwtData jwt
  raw := ""
  if h := req.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[0:7], "BEARER ") {
    raw = h[7:]
  }
  if raw == "" {
    cookie, err := req.Cookie(self.JwtCookieKey)
    if err != nil {
      return nil, err
    }
    raw = cookie.Value
  }
  if raw == "" {
    return nil, fmt.Errorf("jwt not found in auth header, nor cookie")
  }

  // split token into 3 parts and decode payload
  jwtParts := strings.Split(raw, ".")
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

// replaceVarInUrl replaces some substring on specified position by specified value. Position of some substring in
// the url means position in url split by character "/" indexed from 0. So e.g. substring "{var1}" in url
// "/some/{var1}/path/{var2}" has position 1, substring "{var2}" has position 3 etc.
func (self *FromJWT) replaceVarInUrl(url string, varPosition int, newValue string) string {
  var newUrl string
  if url == ""{
    return ""
  }
  parts := strings.Split(url, "/")
  var cleanedParts []string
  // cleanup empty parts
  for _, v := range parts {
    if v != "" {
      cleanedParts = append(cleanedParts, v)
    }
  }
  // replace new value in specified url position
  for i, oldValue := range cleanedParts {
    newUrl += "/"
    if i == varPosition {
      newUrl += newValue
    } else {
      newUrl += oldValue
    }
  }
  // add slash to the end of new url if it was also in an original url
  if url[len(url)-1] == '/' && newUrl[len(newUrl)-1] != '/' {
    newUrl += "/"
  }
  return newUrl
}

// modifyQuerystring rewrites values of specified querystring parameters by specified values from JWT. If specified
// querystring parameter not exists, a new one is created.
func (self *FromJWT) modifyQuerystring(req *http.Request, jwt jwt) error {
  query := req.URL.Query()
  for _, entry := range self.Querystring {
    newVal, ok := jwt[entry.KeyJWT]
    if !ok {
      return fmt.Errorf("key=%s not in jwt", entry.KeyJWT)
    }
    query.Set(entry.Name, fmt.Sprintf("%v", newVal))
    // if there are more parameters with same name (e.g. ?key1=10&key1=20&key1=30), query.Set rewrites this array by
    // one value; so if we want to preserve array of values, we should use query.Set & query.Add (for each query value)
  }
  req.URL.RawQuery = query.Encode()
  return nil
}

// modifyPathParams rewrites path parameter on defined position by specified value from JWT.
func (self *FromJWT) modifyPathParams(req *http.Request, jwt jwt) error {
  for _, entry := range self.PathParam {
    newVal, ok := jwt[entry.KeyJWT]
    if !ok {
      return fmt.Errorf("key=%s not in jwt", entry.KeyJWT)
    }
    req.URL.Path = self.replaceVarInUrl(req.URL.Path, entry.Position, fmt.Sprintf("%v", newVal))
  }
  return nil
}

// modifyPathStrings replaces specified substring (in path) by specified value from JWT.
func (self *FromJWT) modifyPathStrings(req *http.Request, jwt jwt) error {
  for _, entry := range self.PathString {
    newVal, ok := jwt[entry.KeyJWT]
    if !ok {
      return fmt.Errorf("key=%s not in jwt", entry.KeyJWT)
    }
    req.URL.Path = strings.ReplaceAll(req.URL.Path, entry.Name, fmt.Sprintf("%v", newVal))
  }
  return nil
}

// modifyPathStrings rewrites specified key in a json body by specified value from JWT. Nested fields (json paths) and
// json arrays are not supported for now.
func (self *FromJWT) modifyBodyJson(req *http.Request, jwt jwt) error {
  if req.Body == nil || len(self.JsonBody) == 0 || req.Header.Get("Content-type") != "application/json" {
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
      return fmt.Errorf("key=%s not in jwt", entry.KeyJWT)
    }
    bodyData[entry.Name] = newVal
  }
  newBodyBytes, err := json.Marshal(bodyData)
  if err != nil {
    return err
  }
  req.Body = ioutil.NopCloser(bytes.NewBuffer(newBodyBytes))
  return nil
}
