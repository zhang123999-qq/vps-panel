// Package web 把前端构建产物嵌入二进制，实现「单 exe 交付」。
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var embedded embed.FS

// Dist 返回 dist 子树。
func Dist() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}

// Handler 返回静态文件处理器；前端未构建时返回占位页。
func Handler() http.Handler {
	sub, err := Dist()
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(sub))
}
