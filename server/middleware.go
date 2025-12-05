package server

import (
	"fmt"
	"net"
	"time"
)

type RequestMiddleware interface {
	HandleRequest(header *RequestHeaderFactory) error
}

type ResponseMiddleware interface {
	HandleResponse(header *ResponseHeaderFactory, body []byte) error
}

type TunnelFingerprint struct{}

func NewTunnelFingerprint() *TunnelFingerprint {
	return &TunnelFingerprint{}
}
func (h *TunnelFingerprint) HandleRequest(header *RequestHeaderFactory) error {
	return nil
}
func (h *TunnelFingerprint) HandleResponse(header *ResponseHeaderFactory, body []byte) error {
	header.Set("Server", "Tunnel Please")
	return nil
}

type RequestLogger struct {
	interaction Interaction
	remoteAddr  net.Addr
}

func NewRequestLogger(interaction Interaction, remoteAddr net.Addr) *RequestLogger {
	return &RequestLogger{
		interaction: interaction,
		remoteAddr:  remoteAddr,
	}
}

func (rl *RequestLogger) HandleRequest(header *RequestHeaderFactory) error {
	rl.interaction.SendMessage(fmt.Sprintf("\033[32m%s %s -> %s %s \033[0m\r\n", time.Now().UTC().Format(time.RFC3339), rl.remoteAddr.String(), header.Method, header.Path))
	return nil
}

func (rl *RequestLogger) HandleResponse(header *ResponseHeaderFactory, body []byte) error { return nil }

//TODO: Implement caching atau enggak
//const maxCacheSize = 50 * 1024 * 1024
//
//type DiskCacheMiddleware struct {
//	dir       string
//	mu        sync.Mutex
//	file      *os.File
//	path      string
//	cacheable bool
//}
//
//func NewDiskCacheMiddleware() *DiskCacheMiddleware {
//	return &DiskCacheMiddleware{dir: "cache"}
//}
//
//func (c *DiskCacheMiddleware) ensureDir() error {
//	return os.MkdirAll(c.dir, 0755)
//}
//
//func (c *DiskCacheMiddleware) cacheKey(method, path string) string {
//	return fmt.Sprintf("%s_%s.cache", method, base64.URLEncoding.EncodeToString([]byte(path)))
//}
//
//func (c *DiskCacheMiddleware) filePath(method, path string) string {
//	return filepath.Join(c.dir, c.cacheKey(method, path))
//}
//
//func fileExists(path string) bool {
//	_, err := os.Stat(path)
//	if err == nil {
//		return true
//	}
//	if os.IsNotExist(err) {
//		return false
//	}
//	return false
//}
//
//func canCacheRequest(header *RequestHeaderFactory) bool {
//	if header.Method != "GET" {
//		return false
//	}
//
//	if cacheControl := header.Get("Cache-Control"); cacheControl != "" {
//		if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private") || strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "max-age=0") {
//			return false
//		}
//	}
//
//	if header.Get("Authorization") != "" {
//		return false
//	}
//
//	if header.Get("Cookie") != "" {
//		return false
//	}
//
//	return true
//}
//
//func (c *DiskCacheMiddleware) HandleRequest(header *RequestHeaderFactory) error {
//	if !canCacheRequest(header) {
//		c.cacheable = false
//		return nil
//	}
//
//	c.cacheable = true
//	_ = c.ensureDir()
//	path := c.filePath(header.Method, header.Path)
//
//	if fileExists(path + ".finish") {
//		c.file = nil
//		return nil
//	}
//
//	if c.file != nil {
//		err := c.file.Close()
//		if err != nil {
//			return err
//		}
//		err = os.Rename(c.path, c.path+".finish")
//		if err != nil {
//			return err
//		}
//	}
//
//	c.path = path
//	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
//	if err != nil {
//		return err
//	}
//
//	c.file = f
//
//	return nil
//}
//
//func (c *DiskCacheMiddleware) HandleResponse(header *ResponseHeaderFactory, body []byte) error {
//	if !c.cacheable {
//		return nil
//	}
//
//	if c.file == nil {
//		header.Set("X-Cache", "HIT")
//		return nil
//	}
//
//	_, err := c.file.Write(body)
//	if err != nil {
//		return err
//	}
//
//	header.Set("X-Cache", "MISS")
//	return nil
//}
