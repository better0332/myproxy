该项目使用golang开发，可以在windows、linux部署，支持http, https, socks4(a),
socks5代理，该代理可以截获http，https请求(篡改证书)并写入数据库，以便后续分析。

注意：默认连接127.0.0.1上的mysql数据库，详见WebHunter/proxy/db/db.go
表结构见WebHunter.sql(先新建WebHunter数据库，导入WebHunter.sql)
my.cnf 配置:
max_allowed_packet > 2M

下载源码，进入源码目录，执行go build(生成可执行文件)
依赖库：
mysql driver(github.com/go-sql-driver/mysql)

Fake-ACRoot-Certificate.cer：在浏览器中导入该根证书，可以拦截https请求

Fake-ACRoot-Key.pem：根证书私钥

默认代理监听端口是1080
HTTP(S)代理密码：只要用户名密码相同
SOCKS5密码：只要用户名密码不为空

