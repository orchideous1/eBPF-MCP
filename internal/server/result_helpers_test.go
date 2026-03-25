package server

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func firstText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("result has no content")
	}
	text, ok := mcp.AsTextContent(res.Content[0])
	if !ok {
		t.Fatalf("first content is not text")
	}
	return text.Text
}
