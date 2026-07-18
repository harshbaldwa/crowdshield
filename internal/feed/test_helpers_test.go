package feed

import "strings"

func stringsReader(value string) *strings.Reader { return strings.NewReader(value) }
