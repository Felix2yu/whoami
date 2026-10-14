package whoami

import (
	"os"
	"runtime"
	"runtime/debug"
)

// ServerInfo 是服务进程对自身身份的自述，由根路径 GET / 在请求 Accept 不含
// text/html（如 curl 默认 */*）时以 JSON 返回。
// 与 /api/whoami 不同，它描述的是「这台服务器是谁」，不是访客。
type ServerInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	GoVersion     string `json:"go_version"`
	ListenAddr    string `json:"listen_addr"`
	ModulePath    string `json:"module_path"`
	ModuleVersion string `json:"module_version,omitempty"`
	VCSRevision   string `json:"vcs_revision,omitempty"`
	VCSCommitTime string `json:"vcs_commit_time,omitempty"`
	VCSModified   bool   `json:"vcs_modified"`
}

// ServerInfo 采集服务进程自身的身份信息。版本与构建信息取自
// runtime/debug.ReadBuildInfo，无需额外的 ldflags 注入；测试或脱 VCS 构建时
// vcs_* 与 module_version 可能为空，结构体用 omitempty 保证安全留空。
func (s *Server) ServerInfo() ServerInfo {
	info := ServerInfo{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		GoVersion:  runtime.Version(),
		ListenAddr: s.cfg.Addr,
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info.ModulePath = bi.Path
		info.ModuleVersion = bi.Main.Version
		for _, set := range bi.Settings {
			switch set.Key {
			case "vcs.revision":
				info.VCSRevision = set.Value
			case "vcs.time":
				info.VCSCommitTime = set.Value
			case "vcs.modified":
				info.VCSModified = set.Value == "true"
			}
		}
	}
	return info
}
