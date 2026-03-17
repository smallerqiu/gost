CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o gost && upx gost --best --lzma gost


# upx
# upx gost --best --lzma gost

# publish test
rsync -avz gost 2890CC:/home/apps/gost
# rsync -avz gost.toml 2890CC:/home/apps/gost.toml


# run
# gost_test -L=auto://admin:123456@:33080

# systemctl restart gost
# journalctl -u gost -f