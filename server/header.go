package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

type HeaderManager interface {
	Get(key string) []byte
	Set(key string, value []byte)
	Remove(key string)
	Finalize() []byte
}

type ResponseHeaderFactory struct {
	startLine []byte
	headers   map[string]string
}

type RequestHeaderFactory struct {
	Method    string
	Path      string
	Version   string
	startLine []byte
	headers   map[string]string
}

func NewRequestHeaderFactory(r io.Reader) (*RequestHeaderFactory, error) {
	br := bufio.NewReader(r)
	header := &RequestHeaderFactory{
		headers: make(map[string]string),
	}

	startLine, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	startLine = strings.TrimRight(startLine, "\r\n")
	header.startLine = []byte(startLine)

	parts := strings.Split(startLine, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid request line")
	}

	header.Method = parts[0]
	header.Path = parts[1]
	header.Version = parts[2]

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			break
		}

		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		header.headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	return header, nil
}

func NewResponseHeaderFactory(startLine []byte) *ResponseHeaderFactory {
	header := &ResponseHeaderFactory{
		startLine: nil,
		headers:   make(map[string]string),
	}
	lines := bytes.Split(startLine, []byte("\r\n"))
	if len(lines) == 0 {
		return header
	}
	header.startLine = lines[0]
	for _, h := range lines[1:] {
		if len(h) == 0 {
			continue
		}

		parts := bytes.SplitN(h, []byte(":"), 2)
		if len(parts) < 2 {
			continue
		}

		key := parts[0]
		val := bytes.TrimSpace(parts[1])
		header.headers[string(key)] = string(val)
	}
	return header
}

func (resp *ResponseHeaderFactory) Get(key string) string {
	return resp.headers[key]
}

func (resp *ResponseHeaderFactory) Set(key string, value string) {
	resp.headers[key] = value
}

func (resp *ResponseHeaderFactory) Remove(key string) {
	delete(resp.headers, key)
}

func (resp *ResponseHeaderFactory) Finalize() []byte {
	var buf bytes.Buffer

	buf.Write(resp.startLine)
	buf.WriteString("\r\n")

	for key, val := range resp.headers {
		buf.WriteString(key)
		buf.WriteString(": ")
		buf.WriteString(val)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	return buf.Bytes()
}

func (req *RequestHeaderFactory) Get(key string) string {
	val, ok := req.headers[key]
	if !ok {
		return ""
	}
	return val
}

func (req *RequestHeaderFactory) Set(key string, value string) {
	req.headers[key] = value
}

func (req *RequestHeaderFactory) Remove(key string) {
	delete(req.headers, key)
}

func (req *RequestHeaderFactory) Finalize() []byte {
	var buf bytes.Buffer

	buf.Write(req.startLine)
	buf.WriteString("\r\n")

	req.headers["X-HF"] = "modified"

	for key, val := range req.headers {
		buf.WriteString(key)
		buf.WriteString(": ")
		buf.WriteString(val)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	return buf.Bytes()
}
