# ----------------------------
#
#   构建打包
#
# ----------------------------
APP_NAME := gost

.PHONY: all
all: build

#
.PHONY: build
build:
	@echo ">> Compile $(APP_NAME) ..."
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(APP_NAME) main.go
	@ls -lh |grep $(APP_NAME)

