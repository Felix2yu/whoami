# whoami —— 目标约定见 Felix2yu/.github/docs/makefile.md
#
# 七个必备目标：build / dev / test / lint / fmt / docker / clean
# 其余目标按仓库自身需要添加。
.PHONY: build dev test lint lint-strict fmt docker clean

BIN  := bin/whoami
MAIN := ./cmd/whoami

## 产出 $(BIN)。无前端构建；build.sh 交叉编译到 linux/amd64 供镜像使用
build:
	./scripts/build.sh

## 本地起服务（端口 9099）
dev:
	go run $(MAIN)

test:
	go test ./...

lint:
	go vet ./...

lint-strict: lint
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else echo "  （未安装 golangci-lint，跳过）"; fi

fmt:
	gofmt -w $$(git ls-files '*.go')

docker: build
	docker build -t whoami:dev .

clean:
	rm -rf bin
