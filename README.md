# Log4j2 Vulnerability Local Scanner (CVE-2021-45046)

Log4j 漏洞本地检测脚本，扫描主机上所有java进程，检测是否引入了有漏洞的log4j-core jar包，是否可能遭到远程代码执行攻击（CVE-2021-45046）。上传扫描报告到指定的服务器。

Scan all java processes on your host to check weather it's affected by log4j2 remote code execution(CVE-2021-45046), then upload the report to your api server. 

Works under python2.7 / 2.6 / 3.x, no extra lib required.

## Change Log
* 2021-12-22 增加 log4j-core/pom.properties 版本检测

## 扫描逻辑

1. 遍历主机上的`java`进程
2. 遍历`java`进程打开的jar包
3. 查找`log4j-core-*` jar包
4. 递归解压其他 jar包，查找`log4j-core-*` jar包
5. 在log4j-core jar包中，查找`JndiLookup.class`
6. 找到`JndiLookup.class`后，根据其版本号 、jvm参数、OS环境变量、是否docker容器进程、k8s进程，输出是否存在漏洞，输出升级提示
7. 上传扫描结果到指定的服务器

## How It Works

* Find all `java` process on the host
* Find all `jar` files open by the `java` process
* Search for `log4j-core-*.jar` 
* Recursively unzip other jar files，search for `log4j-core-*.jar` 
* Search for `JndiLookup.class` in `log4j-core-*.jar`
* Once `JndiLookup.class` found，output some tips based on its version 、jvm args、OS env args、is docker container、is k8s
* Upload full report to your api server 

## 稳定机制

* 递归：递归解压缩jar包，最多不超过5层
* 内存：每次解压都检测自身内存占用，至多不超过300MB。超过则跳过扫描，上报部分结果和内存错误
* 网络：扫描结束后，随机sleep 0~100秒，假设13万主机，则每秒上报的服务器大约只有1300台

## 批量扫描

可以集成到Agent，或者下发该扫描脚本一次性执行。也可以运维机登入，一键全网扫描。

You can use the script as a module by your agent, or deliver and run it only once.  

Those who don't have an easy to use agent can run command below on your OPS server.

```
cat hosts.txt|xargs -P 5 -I{} sh -c 'ssh root@{} -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "wget http://your_site/to_download/log4j2_vul_scanner.py -O /tmp/log4j2_vul_scanner.py -q && python /tmp/log4j2_vul_scanner.py && /usr/bin/rm /tmp/log4j2_vul_scanner.py" > ./logs.txt||exit 0'
```

