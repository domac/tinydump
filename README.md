tinydump
========

简单的网络嗅探工具, 类似tcpdump, 采用go编写


### 使用方式

#### 构建二进制文件

```
//mac 版本
GOOS=darwin  go build


//linux 版本
GOOS=linux  go build
```

#### 命令参数

```
sudo ./tinydump -h

 [ -i interface ]
 [ -t timeout ]
 [ -s snaplen ]
 [ -X hexdump ]
 [ -d dump file ]
 [ -r read file ]
 [ -h show usage]
 [ expression ]
```

例子:

1.直接使用

```
$ sudo ./tinydump 
```

2.host过滤

```
$ sudo ./tinydump 'src 192.168.1.101 or dst 192.168.1.101'
```

3.端口过滤

```
$ sudo ./tinydump 'port 8000'
```