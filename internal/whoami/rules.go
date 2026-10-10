package whoami

// 判定分类：同一 Category 内出现两个不同 Name 才算冲突，
// 所以「Linux」和「统信 UOS」不会互相打架，它们分属 platform 与 os。
const (
	CatPlatform = "platform"
	CatOS       = "os"
	CatCPU      = "cpu"
	CatBrowser  = "browser"
	CatEngine   = "engine"
	CatGPU      = "gpu"
)

// 置信度阈值：>=Confirmed 判「确认」，>=Suspect 判「疑似」，其余「未知」。
const (
	ConfidenceConfirmed = 80
	ConfidenceSuspect   = 40
)

// Rule 是一条可追加的识别规则。规则表是数据，不是代码：
// 追加一个 token 只需要往 BuiltinRules 或外部 JSON 里加一条，不动匹配与打分逻辑。
type Rule struct {
	ID    string `json:"id"`
	Field string `json:"field"`
	Match Match  `json:"match"`

	Name     string `json:"name"`     // 展示名
	Domain   string `json:"domain"`   // 中文归类，页面分组用
	Category string `json:"category"` // 程序分组，冲突判定用

	Domestic  bool `json:"domestic"`  // 国产
	Xinchuang bool `json:"xinchuang"` // 属于信创范畴
	// Foreign 是「确证在信创目录之外」的平台信号。信创终端的前提是跑国产操作系统，
	// 所以 macOS/Windows 这类系统家族信号足以给出否定结论——
	// 与「判不出来」的 unknown 是两件事，别混用。
	Foreign bool `json:"foreign"`

	Weight int `json:"weight"` // 单独命中时的基础分，用于页面展示证据强度
	// Ceiling 是「信创判定分」的上限：单靠这条信号最多能把结论推到多可信，
	// 代表检测方法本身的天花板，跨源一致也突破不了它。
	Ceiling int `json:"ceiling"`

	// Suppresses 列出应被本规则压制的规则 ID，例如安卓的 ARM 不该被当成飞腾/鲲鹏。
	Suppresses []string `json:"suppresses,omitempty"`

	// Verified 表示该 token 已在公开 UA 语料里证实存在；
	// false 的规则是预留条目，命中概率未知，页面会提示「待实测」。
	Verified bool   `json:"verified"`
	Note     string `json:"note"`
}

// r 是构造规则的行内助手，让表格保持可读的宽度。
func r(id, field string, m Match, name, domain, cat string, weight, ceiling int, note string) Rule {
	return Rule{ID: id, Field: field, Match: m, Name: name, Domain: domain, Category: cat,
		Weight: weight, Ceiling: ceiling, Verified: true, Note: note}
}

func (ru Rule) xc() Rule {
	ru.Xinchuang = true
	return ru
}

func (ru Rule) cn() Rule {
	ru.Domestic = true
	return ru
}

func (ru Rule) foreign() Rule {
	ru.Foreign = true
	return ru
}

func (ru Rule) unverified() Rule {
	ru.Verified = false
	return ru
}

func (ru Rule) suppress(ids ...string) Rule {
	ru.Suppresses = ids
	return ru
}

// BuiltinRules 是内置规则表。
func BuiltinRules() []Rule {
	w := func(tokens ...string) Match { return Match{Word: tokens, CaseFold: true} }
	c := func(tokens ...string) Match { return Match{Contains: tokens, CaseFold: true} }
	e := func(tokens ...string) Match { return Match{Equals: tokens, CaseFold: true} }
	re := func(patterns ...string) Match { return Match{Regex: patterns, CaseFold: true} }

	var out []Rule

	// --- 系统家族（FieldPlatform）：境外桌面/服务器系统可以直接给出否定结论，
	// 安卓与鸿蒙不给——国产平板和鸿蒙兼容层同样报 Android，判「不是」会误伤。
	out = append(out,
		r("plat-linux", FieldPlatform, e("linux"), "Linux", "系统家族", CatPlatform, 90, 0, "Linux 家族，具体发行版看下面的信号。"),
		r("plat-windows", FieldPlatform, e("windows"), "Windows", "系统家族", CatPlatform, 90, 0,
			"信创终端要跑国产操作系统，Windows 不在目录内。").foreign().
			suppress("cpu-aarch64"),
		r("plat-macos", FieldPlatform, e("macos"), "macOS", "系统家族", CatPlatform, 90, 0,
			"Safari 的 UA 精简，Apple 芯片与 Intel 无法从 UA 区分；但 macOS 本身就不在信创目录内。").foreign().
			suppress("cpu-aarch64"),
		r("plat-android", FieldPlatform, e("android"), "Android", "系统家族", CatPlatform, 90, 0, "安卓设备上报的 ARM 与信创无关。").
			suppress("cpu-aarch64", "cpu-riscv64"),
		r("plat-ios", FieldPlatform, e("ios"), "iOS/iPadOS", "系统家族", CatPlatform, 90, 0,
			"iOS/iPadOS 不在信创目录内。").foreign().
			suppress("cpu-aarch64", "cpu-riscv64"),
		r("plat-chromeos", FieldPlatform, e("chromeos"), "ChromeOS", "系统家族", CatPlatform, 90, 0,
			"ChromeOS 不在信创目录内。").foreign().
			suppress("cpu-aarch64"),
		r("plat-harmonyos", FieldPlatform, e("harmonyos"), "HarmonyOS", "系统家族", CatPlatform, 90, 0, "国产移动系统，不属于信创 PC/服务器范畴。").
			cn().suppress("cpu-aarch64", "cpu-riscv64"),
		// BSD 与信创无关：其上的 ARM/RISC-V 一样不参与信创判定。
		r("plat-freebsd", FieldPlatform, e("freebsd"), "FreeBSD", "系统家族", CatPlatform, 90, 0,
			"FreeBSD 不在信创目录内。").foreign().
			suppress("cpu-aarch64", "cpu-riscv64"),
		r("plat-openbsd", FieldPlatform, e("openbsd"), "OpenBSD", "系统家族", CatPlatform, 90, 0,
			"OpenBSD 不在信创目录内。").foreign().
			suppress("cpu-aarch64", "cpu-riscv64"),
		r("plat-netbsd", FieldPlatform, e("netbsd"), "NetBSD", "系统家族", CatPlatform, 90, 0,
			"NetBSD 不在信创目录内。").foreign().
			suppress("cpu-aarch64", "cpu-riscv64"),
	)

	// --- CPU 架构（FieldArch）：最硬的信创信号 ---
	out = append(out,
		r("cpu-loongarch64", FieldArch, e("loongarch64", "loongarch"), "龙芯 LoongArch", "CPU 架构", CatCPU, 100, 100,
			"LoongArch 自研指令集只在龙芯上出现，x86/ARM 机器不会偶然上报。").xc(),
		r("cpu-sw64", FieldArch, e("sw_64", "sw64"), "申威 SW-64", "CPU 架构", CatCPU, 100, 100,
			"申威指令集为国产自主，基本等价于信创终端。").xc(),
		r("cpu-mips64", FieldArch, e("mips64", "mips"), "龙芯 MIPS（旧世界）", "CPU 架构", CatCPU, 90, 100,
			"3A 之前的龙芯上报 mips/mips64；也可能是 MIPS 路由器等非终端设备，建议与发行版信号交叉。").xc(),
		r("cpu-aarch64", FieldArch, e("aarch64", "arm64"), "ARM 64 位", "CPU 架构", CatCPU, 55, 50,
			"飞腾/鲲鹏是信创主力，但树莓派、安卓机与 Apple 芯片同样上报 aarch64，单靠它只能判疑似。").xc(),
		r("cpu-riscv64", FieldArch, e("riscv64", "riscv"), "RISC-V", "CPU 架构", CatCPU, 45, 40,
			"国产 RISC-V 生态仍在早期，暂不参与信创判定。"),
		r("cpu-arm32", FieldArch, e("arm"), "ARM 32 位", "CPU 架构", CatCPU, 20, 20, "嵌入式特征，与信创无关。"),
		r("cpu-ppc64", FieldArch, e("ppc64", "powerpc"), "PowerPC 64", "CPU 架构", CatCPU, 15, 15,
			"IBM Power 架构，国际生态，与信创无关。"),
		r("cpu-x8664", FieldArch, e("x86_64", "x86_32"), "x86", "CPU 架构", CatCPU, 10, 10,
			"海光、兆芯是国产 x86，但任何 HTTP 信号都无法把它们与 Intel/AMD 区分开——这是本检测方法的天花板，不是访客机器的证据。"),
	)

	// --- 发行版（FieldUA）：已证实 token 在前，预留条目在后 ---
	out = append(out,
		r("os-uos", FieldUA, w("uos"), "统信 UOS", "发行版", CatOS, 95, 100,
			"UA 中的 UOS 字段来自统信定制 Chromium 构建。").xc(),
		r("os-uniontech", FieldUA, c("uniontech"), "统信 UOS", "发行版", CatOS, 95, 100,
			"uniontech 是统信软件的域名标识。").xc(),
		// "Ubuntu Kylin"/"Open Kylin" 里的 kylin 指优麒麟/开放麒麟，不是银河麒麟，
		// 整词匹配必须把这两种写法排掉，否则同一台机器会出两条互斥的信创结论。
		r("os-kylin", FieldUA, Match{Word: []string{"kylin"}, Not: &Match{Contains: []string{"ubuntu kylin", "open kylin"}}, CaseFold: true},
			"银河麒麟 / 中标麒麟", "发行版", CatOS, 95, 100, "麒麟系发行版的 UA 标识。").xc(),
		r("os-kylinos", FieldUA, c("kylinos", "kylin-desktop"), "银河麒麟 / 中标麒麟", "发行版", CatOS, 95, 100,
			"粘连写法的 kylinos 整词匹配不到 kylin，需要单独一条。").xc(),
		r("os-deepin", FieldUA, w("deepin"), "deepin 深度", "发行版", CatOS, 80, 60,
			"deepin 是社区发行版，信创目录内是其商业版统信 UOS；命中它说明是国产 Linux，但是否信创机型要再交叉。").xc(),
		r("os-openeuler", FieldUA, c("openeuler"), "openEuler 欧拉", "发行版", CatOS, 75, 60,
			"服务器侧国产 OS，UA 里能否稳定出现该 token 待实测。").xc().unverified(),
		r("os-anolis", FieldUA, c("anolis"), "Anolis 龙蜥", "发行版", CatOS, 75, 60,
			"阿里系国产服务器 OS，UA token 待实测。").xc().unverified(),
		r("os-fangde", FieldUA, c("fangde"), "中科方德 NFS", "发行版", CatOS, 70, 60,
			"信创桌面发行版之一，UA token 待实测。").xc().unverified(),
		r("os-puhua", FieldUA, c("pvdrvos", "secos"), "普华 OS", "发行版", CatOS, 70, 60,
			"信创桌面发行版之一，UA token 待实测。").xc().unverified(),
		r("os-openkylin", FieldUA, c("openkylin", "open kylin"), "openKylin 开放麒麟", "发行版", CatOS, 80, 60,
			"开放麒麟社区发行版，命中说明是国产 Linux，是否信创机型需与架构信号交叉。").xc().unverified(),
		r("os-ubuntukylin", FieldUA, c("ubuntukylin", "ubuntu kylin"), "优麒麟 Ubuntu Kylin", "发行版", CatOS, 75, 60,
			"优麒麟基于 Ubuntu 的国产定制发行版，是否信创机型需与架构信号交叉。").xc().unverified(),
		r("os-loongnix", FieldUA, c("loongnix"), "Loongnix 龙芯发行版", "发行版", CatOS, 95, 100,
			"Loongnix 是龙芯官方发行版，只出现在龙芯平台。").xc().unverified(),
	)

	// --- 国际发行版（FieldUA）：token 来自 uap-core 公开语料与 Firefox/Chromium 的
	// 发行版定制 UA（如 "(X11; Ubuntu; Linux x86_64)"）。只做识别展示，不参与信创判定。
	out = append(out,
		r("os-ubuntu", FieldUA, w("ubuntu", "kubuntu", "lubuntu"), "Ubuntu", "发行版", CatOS, 80, 0,
			"Firefox 与 Ubuntu 版 Chromium 的 UA 会带发行版名。"),
		r("os-debian", FieldUA, w("debian"), "Debian", "发行版", CatOS, 80, 0, "uap-core 公开语料 token。"),
		r("os-fedora", FieldUA, w("fedora"), "Fedora", "发行版", CatOS, 80, 0, "Firefox 的 Fedora 构建 UA。"),
		r("os-centos", FieldUA, w("centos"), "CentOS", "发行版", CatOS, 80, 0, "uap-core 公开语料 token。"),
		r("os-redhat", FieldUA, w("red hat", "redhat"), "Red Hat / RHEL", "发行版", CatOS, 80, 0, "uap-core 公开语料 token。"),
		r("os-opensuse", FieldUA, w("opensuse", "suse"), "openSUSE / SUSE", "发行版", CatOS, 80, 0, "uap-core 公开语料 token。"),
		r("os-arch", FieldUA, w("arch linux"), "Arch Linux", "发行版", CatOS, 80, 0, "uap-core 公开语料 token。"),
		r("os-gentoo", FieldUA, w("gentoo"), "Gentoo", "发行版", CatOS, 80, 0, "uap-core 公开语料 token。"),
		r("os-mint", FieldUA, w("linux mint"), "Linux Mint", "发行版", CatOS, 80, 0, "uap-core 公开语料 token。"),
		r("os-freebsd", FieldUA, w("freebsd"), "FreeBSD", "发行版", CatOS, 80, 0, "Firefox 的 FreeBSD 构建 UA。"),
		// LCTE 出现在公开 UA 语料的 IE11 政务定制 Windows 中，是 x86 Windows，
		// 只做识别展示，不参与信创判定。
		r("os-lcte", FieldUA, w("lcte"), "政务版 Windows（LCTE）", "发行版", CatOS, 70, 30,
			"公开 UA 语料中出现在 IE11 的政务定制 Windows（疑似神州网信政府版），x86 架构与信创无关。").cn(),
	)

	// --- 浏览器（FieldUA / FieldBrand）---
	out = append(out,
		r("browser-kylin", FieldUA, c("kylinbrowser", "kylin browser"), "麒麟浏览器", "浏览器", CatBrowser, 90, 100,
			"麒麟浏览器随银河麒麟发行，命中即说明系统在麒麟上跑。").xc(),
		r("browser-uos", FieldUA, re(`(uos|uniontech)[ _-]?browser`), "统信浏览器", "浏览器", CatBrowser, 90, 100,
			"统信自家浏览器，UA 带 UOSBrowser 类标识。").xc(),
		r("browser-qax", FieldUA, re(`qax[ _-]?browser`), "奇安信浏览器", "浏览器", CatBrowser, 80, 75,
			"信创场景常见，但也有 Windows 版，单凭它不能确定终端 OS 是国产。").xc(),
		r("browser-honglian", FieldUA, c("honglian", "redlotus"), "红莲花浏览器", "浏览器", CatBrowser, 70, 60,
			"信创定制浏览器，UA token 待实测。").xc().unverified(),
		r("browser-360", FieldUA, c("360se", "360ee", "360chrome", "360aibrowser", "360 浏览器"), "360 浏览器", "浏览器", CatBrowser, 70, 30,
			"国产浏览器，但运行在任意系统上，不能作为信创终端证据。").cn(),
		r("browser-qq", FieldUA, c("qqbrowser", "mqqbrowser"), "QQ 浏览器", "浏览器", CatBrowser, 70, 30,
			"国产浏览器，非信创终端证据。").cn(),
		r("browser-sogou", FieldUA, c("metasr", "sogoumobilebrowser", "sogoumse"), "搜狗浏览器", "浏览器", CatBrowser, 70, 30,
			"PC 版带 MetaSr，手机版带 SogouMobileBrowser，均为公开语料证实的 token。").cn(),
		r("browser-uc", FieldUA, c("ucbrowser", "ucweb", "ubrowser"), "UC 浏览器", "浏览器", CatBrowser, 70, 30,
			"PC 版 UBrowser、手机版 UCBrowser，公开语料证实。").cn(),
		r("browser-maxthon", FieldUA, c("maxthon"), "傲游浏览器", "浏览器", CatBrowser, 70, 30, "国产浏览器。").cn(),
		r("browser-liebao", FieldUA, c("lbbrowser", "liebaofast"), "猎豹浏览器", "浏览器", CatBrowser, 70, 30,
			"PC 版 LBBROWSER、手机版 liebaofast，公开语料证实。").cn(),
		r("browser-2345", FieldUA, c("2345chrome", "2345air"), "2345 浏览器", "浏览器", CatBrowser, 70, 30, "国产壳浏览器。").cn(),
		r("browser-tencent", FieldUA, c("tencenttraveler"), "TT 浏览器", "浏览器", CatBrowser, 70, 30, "国产壳浏览器。").cn(),
		// 国产移动端浏览器：token 均在 uap-core 公开语料或国内 UA 语料站中证实。
		r("browser-huawei", FieldUA, c("huaweibrowser"), "华为浏览器", "浏览器", CatBrowser, 70, 30,
			"华为浏览器随 EMUI/HarmonyOS 分发。").cn(),
		r("browser-miui", FieldUA, c("miuibrowser"), "小米浏览器", "浏览器", CatBrowser, 70, 30, "MIUI/HyperOS 自带浏览器。").cn(),
		r("browser-heytap", FieldUA, c("heytapbrowser", "oppobrowser"), "OPPO 浏览器", "浏览器", CatBrowser, 70, 30,
			"新标识 HeyTapBrowser、旧标识 OppoBrowser，公开语料证实。").cn(),
		r("browser-vivo", FieldUA, c("vivobrowser"), "vivo 浏览器", "浏览器", CatBrowser, 70, 30, "vivo 自带浏览器。").cn(),
		r("browser-quark", FieldUA, c("quark/", "quarkpc"), "夸克浏览器", "浏览器", CatBrowser, 70, 30,
			"阿里夸克，uap-core 与国内 UA 语料均证实 Quark/ 与 QuarkPC token。").cn(),
		r("browser-honor", FieldUA, c("honorbrowser"), "荣耀浏览器", "浏览器", CatBrowser, 70, 30,
			"荣耀浏览器，uap-core 公开语料证实（含 bdhonorbrowser 变体）。").cn(),
		r("browser-baidu", FieldUA, c("baiduboxapp"), "百度 App 内置浏览器", "浏览器", CatBrowser, 70, 30,
			"百度 App/手机百度的内置 WebView 标识，公开语料证实。").cn(),
		r("browser-chrome", FieldUA, re(`chrome/[\d.]`), "Google Chrome / Chromium", "内核", CatEngine, 90, 0, ""),
		r("browser-edge", FieldUA, re(`edg(e|a|ios)?/[\d.]`), "Microsoft Edge", "内核", CatEngine, 90, 0, ""),
		r("browser-firefox", FieldUA, re(`firefox/[\d.]`), "Firefox", "内核", CatEngine, 90, 0, ""),
		r("browser-safari", FieldUA, re(`version/[\d.]+ safari/`), "Safari", "内核", CatEngine, 90, 0, ""),
		// Opera 15+ 用 OPR/，Vivaldi 在 UA 尾部自带版本 token，两者都同时携带 Chrome/，
		// 同类别并存不算冲突（只有信创结论参与冲突判定）。
		r("browser-opera", FieldUA, c("opr/"), "Opera", "内核", CatEngine, 90, 0, "Opera 15 之后的 UA 标识。"),
		r("browser-vivaldi", FieldUA, c("vivaldi/"), "Vivaldi", "内核", CatEngine, 85, 0, "Vivaldi UA 尾部标识。"),
		// Client Hints 的品牌名与 UA 规则同名，命中即形成跨源一致，能把结论从「疑似」抬到「确认」。
		r("brand-chrome", FieldBrand, e("google chrome"), "Google Chrome / Chromium", "内核", CatEngine, 90, 0, ""),
		r("brand-chromium", FieldBrand, e("chromium"), "Google Chrome / Chromium", "内核", CatEngine, 80, 0, ""),
		r("brand-edge", FieldBrand, e("microsoft edge"), "Microsoft Edge", "内核", CatEngine, 90, 0, ""),
		r("brand-firefox", FieldBrand, e("firefox"), "Firefox", "内核", CatEngine, 90, 0, ""),
		r("brand-kylin", FieldBrand, c("kylin"), "麒麟浏览器", "浏览器", CatBrowser, 90, 100,
			"定制构建若在 Client Hints 品牌里带上麒麟，可与 UA 信号交叉确认。").xc().unverified(),
		r("brand-uos", FieldBrand, c("uos"), "统信浏览器", "浏览器", CatBrowser, 90, 100,
			"定制构建若在 Client Hints 品牌里带上统信，可与 UA 信号交叉确认。").xc().unverified(),
	)

	// --- GPU（FieldGPU，只有 JS 能拿到）---
	out = append(out,
		r("gpu-jingjiamicro", FieldGPU, re(`jingjia|景嘉微|\bjm[0-9]`), "景嘉微 GPU", "GPU", CatGPU, 85, 90,
			"景嘉微 JS/JM 系列几乎只出现在信创整机上。").xc(),
		r("gpu-moorethreads", FieldGPU, re(`moore ?threads|\bmtt\b`), "摩尔线程 GPU", "GPU", CatGPU, 85, 85,
			"摩尔线程 MTT 系列为国产显卡。").xc(),
		r("gpu-loongson", FieldGPU, c("loongson"), "龙芯集成显卡", "GPU", CatGPU, 80, 80, "GPU 串里带 Loongson 基本可定龙芯平台。").xc(),
		r("gpu-innosilicon", FieldGPU, c("innosilicon"), "芯动科技 GPU", "GPU", CatGPU, 75, 70, "国产 GPU，覆盖面小。").xc(),
		// WebGL 串不受 https 限制，是 UA 被策略冻结时唯一还能说出整机身份的字段。
		// Apple 显卡只随 Apple 整机出货，而 macOS/iOS 本身就不在信创目录内，所以它可以给否定结论。
		r("gpu-apple", FieldGPU, w("apple"), "Apple 显卡", "GPU", CatGPU, 90, 0,
			"Apple GPU 只出现在 Apple 整机上，而 macOS/iOS 不在信创目录内。WebGL 串不受 https 限制，UA 被冻结时它仍有效。").foreign(),
		// 境外显卡**不给**否定结论：国产整机同样可能插 Intel/NVIDIA 独显，
		// 判「不是」的权力只留给能确定整机的信号（系统家族、Apple 显卡、国产指令集）。
		r("gpu-foreign", FieldGPU, c("nvidia", "geforce", "quadro", "radeon", "amd", "intel",
			"uhd graphics", "hd graphics", "iris", "adreno", "mali", "powervr"), "境外显卡", "GPU", CatGPU, 60, 0,
			"境外厂商的显卡，但不构成否定结论：海光、兆芯的整机也可能插 Intel/NVIDIA 独显。"),
		r("gpu-vm", FieldGPU, c("virtualbox", "vmware", "qemu", "bochs", "virtio", "basic render driver"),
			"虚拟/云桌面显卡", "GPU", CatGPU, 60, 0,
			"这是虚拟机或云桌面的虚拟 GPU，看到的不是物理终端的显卡，别拿它判断终端归属。"),
		r("gpu-software", FieldGPU, re(`swiftshader|llvmpipe|software`), "软件渲染", "GPU", CatGPU, 0, 0,
			"拿不到真实 GPU：WebGL 被禁用、走软件渲染或被策略屏蔽 unmasked 参数。此项不构成任何否定结论。"),
	)

	return out
}

func categoryLabel(cat string) string {
	switch cat {
	case CatPlatform:
		return "系统家族"
	case CatOS:
		return "发行版"
	case CatCPU:
		return "CPU 架构"
	case CatBrowser:
		return "浏览器"
	case CatEngine:
		return "渲染内核"
	case CatGPU:
		return "GPU"
	default:
		return cat
	}
}
