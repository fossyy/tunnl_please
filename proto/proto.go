/*
Package proto provides byte-level interaction with HTTP request payload.

Example of HTTP payload for future references, new line symbols escaped:

	POST /upload HTTP/1.1\r\n
	User-Agent: Gor\r\n
	Content-Length: 11\r\n
	\r\n
	Hello world

	GET /index.html HTTP/1.1\r\n
	User-Agent: Gor\r\n
	\r\n
	\r\n

https://github.com/buger/goreplay/blob/master/proto/proto.go
*/
package proto

import (
	"bytes"
	"net/http"
)

var Methods = [...]string{
	http.MethodConnect, http.MethodDelete, http.MethodGet,
	http.MethodHead, http.MethodOptions, http.MethodPatch,
	http.MethodPost, http.MethodPut, http.MethodTrace,
}

func Method(payload []byte) []byte {
	end := bytes.IndexByte(payload, ' ')
	if end == -1 {
		return nil
	}

	return payload[:end]
}

func IsHttpRequest(payload []byte) bool {
	method := string(Method(payload))
	var methodFound bool
	for _, m := range Methods {
		if methodFound = method == m; methodFound {
			break
		}
	}
	return methodFound
}
