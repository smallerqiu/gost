GOOS=linux GOARCH=amd64 go build -o gost



rsync -avz gost root@192.168.2.186:/root/gost/gost
rsync -avz gost root@192.168.3.35:/root/gost/gost
rsync -avz gost root@192.168.3.40:/root/gost/gost