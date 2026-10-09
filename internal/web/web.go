// Package web 存放被 go:embed 打进二进制的页面资源。
// 与 internal/whoami 分开是因为 embed 指令要求资源在同目录下。
package web

import "embed"

// Static 是页面模板与前端资源。追加文件只需要往下面的列表里加一行。
//
//go:embed templates/index.html.tmpl static/app.css
var Static embed.FS
