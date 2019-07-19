package martian

import (
  "testing"
)

func TestReplaceVarInUrl(t *testing.T) {
  var m FromJWT
  expectedUrl := "/v1/files/2/specs/{specID}/"
  url := m.replaceVarInUrl("/v1/files/{fileID}/specs/{specID}/", 2, "2")
  if url != expectedUrl {
    t.Errorf("unexpected url, got %v, expeced: %v", url, expectedUrl)
  }
  expectedUrl = "/v1/files/{fileID}/specs/4"
  url = m.replaceVarInUrl("/v1/files/{fileID}/specs/{specID}", 4, "4")
  if url != expectedUrl {
    t.Errorf("unexpected url, got %v, expeced: %v", url, expectedUrl)
  }
  expectedUrl = "/v1"
  url = m.replaceVarInUrl("/v1", 4, "4")
  if url != expectedUrl {
    t.Errorf("unexpected url, got %v, expeced: %v", url, expectedUrl)
  }
  expectedUrl = "/newValue"
  url = m.replaceVarInUrl("oldValue", 0, "newValue")
  if url != expectedUrl {
    t.Errorf("unexpected url, got %v, expeced: %v", url, expectedUrl)
  }
}
