#!/bin/bash

# author: https://t.me/iu536

clear
echo "Hello! 欢迎使用Trojan+gRPC+tls脚本"
echo "作者:https://t.me/iu536"
echo

read -p "请输入你的域名:" domain

if [ -z $domain ]
  then
         clear
         echo "别闹，你还没输入域名"
	 sleep 2
	 read -p "请输入你的域名:" domain
	  if [ -z $domain ]
	   then
	   echo "? 你还是没输入域名。。不玩了，两秒后退出脚本"
	   echo
	   sleep 2
	   exit
	  fi
fi

read -p "你想要什么端口? 默认443:" port
if [ -z $port ]
 then port=443
fi

read -p "输入你的Trojan密码 [默认abc123666]:" passwd
if [ -z $passwd ]
 then passwd=abc123666
fi

echo -e "你想要什么样的伪装站?\n"
read -p "1.游戏直播; 2.影视站; 3.视频分享平台[默认2]:" checkweb
if [ -z $checkweb ]
 then checkweb=2
fi

mkdir /xray

#开bbr
checkbbr=`lsmod | grep bbr`

if test -z "$checkbbr" 
  then 
       echo "检测到你的系统未开启BBR!"
        echo
        read -p "是否开启bbr? [y/n] Default 'y':" checkbbragain
         if checkbbr=='y' || [ -z $checkbbragain ]
          then
                echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
                echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
                sysctl -p
				echo "BBR开启成功！"
				sleep 1   
         fi
  
  else    
       echo "检测到你的系统已经开启BBR啦！"
	   sleep 1 	
fi

clear
echo "OK! 一切已准备就绪，按回车键开始安装!"
read

#申请证书
apt update
mkdir -p /xray/tls
apt install socat -y
curl https://get.acme.sh | sh
ln -s  /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
source ~/.bashrc
acme.sh --set-default-ca --server letsencrypt
acme.sh --issue -d $domain --standalone -k ec-256 --force
acme.sh --installcert -d $domain --ecc  --key-file   /xray/tls/server.key   --fullchain-file /xray/tls/server.crt
if `test -s /xray/tls/server.crt` 
  then 
        echo -e "证书申请成功!\n"
        echo -n "证书路径:"
        echo
        echo -e "/xray/tls/server.crt"
        echo -e "/xray/tls/server.key\n"
else
        echo "证书安装失败！请检查原因！有问题可联系telegram @iu536"
	exit
fi

#下载xray内核
wget https://github.com/XTLS/Xray-core/releases/download/v1.7.5/Xray-linux-64.zip
apt-get install unzip -y
unzip Xray-linux-64.zip -d /xray
chmod 777 /xray
cat << EOF > /xray/config.json
{
    "log": {
        "loglevel": "warning", 
        "error": "/xray/error.log", 
        "access": "/xray/access.log"
    }, 
    "inbounds": [
        {
            "port": 16969, 
            "listen": "127.0.0.1", 
            "protocol": "trojan", 
            "tag": "trojan_grpc", 
            "settings": {
                "clients": [
                    {
                        "password": "$passwd", 
                        "email": "yourmail@gmail.com"
                    }
                ]
            }, 
            "streamSettings": {
                "network": "grpc", 
                "security": "none", 
                "grpcSettings": {
                    "serviceName": "trojan_grpc"
                }
            }
        }
    ], 
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF

cat << EOF > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/xray/xray run -config /xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
systemctl start xray.service
systemctl enable xray.service

#安装nginx
apt install curl gnupg2 ca-certificates lsb-release debian-archive-keyring -y
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
gpg --dry-run --quiet --import --import-options import-show /usr/share/keyrings/nginx-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/debian `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
apt update
apt install nginx -y
nginx -v
echo "Nginx安装成功!"

#伪装站
mkdir /web
if checkweb=='1'
 then
         wget https://raw.githubusercontent.com/LSitao/Trojan-gRPC-tls/main/web/game.tar.gz
         tar -zxvf game.tar.gz -C /web
	     
elif checkweb=='2'
  then 
         wget https://raw.githubusercontent.com/LSitao/Trojan-gRPC-tls/main/web/movie.tar.gz
	     tar -zxvf movie.tar.gz -C /web

elif checkweb=='3'
  then 
         wget https://raw.githubusercontent.com/LSitao/Trojan-gRPC-tls/main/web/share.tar.gz
	     tar -zxvf share.tar.gz -C /web
	     cd /web/share
	     mv ./* ..
	     cd

fi

#配置nginx
if [ $port -eq 443 ]
 then
cat << EOF > /etc/nginx/conf.d/grpc_proxy.conf
server {
    listen 80;
    server_name ${domain};
    #charset utf-8;   
    
    location / {
    rewrite (.*) https://${domain}\$1 permanent;
      }
}
server {
    listen 443 ssl http2;
    server_name ${domain};
   location /trojan_grpc {
        if (\$content_type !~ "application/grpc") {
                return 404;
        }
        client_max_body_size 512K;
        client_body_timeout 1071906480m;
        grpc_set_header X-Real-IP \$remote_addr;  # cdn $proxy_add_x_forwarded_for
        grpc_read_timeout 1071906480m;
        grpc_pass grpc://127.0.0.1:16969;
    }
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; # 启用HSTS
    location / {
        if (\$host ~* "\d+\.\d+\.\d+\.\d+") { # 禁止以ip方式访问网站
                return 400;
        }
              root /web;
	      index index.html;
    }
    ssl_certificate /xray/tls/server.crt;
    ssl_certificate_key /xray/tls/server.key;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.3;
    ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
    ssl_prefer_server_ciphers on;
}
EOF
else cat << EOF > /etc/nginx/conf.d/grpc_proxy.conf
server {
    listen $port ssl http2;
    server_name ${domain};
    error_page 497 https://\$host:$port\$request_uri;
	
    location /trojan_grpc {
        if (\$content_type !~ "application/grpc") {
                return 404;
        }
        client_max_body_size 512K;
        client_body_timeout 1071906480m;
        grpc_set_header X-Real-IP \$remote_addr;  # cdn $proxy_add_x_forwarded_for
        grpc_read_timeout 1071906480m;
        grpc_pass grpc://127.0.0.1:16969;
    }
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; # 启用HSTS
    location / {
        if (\$host ~* "\d+\.\d+\.\d+\.\d+") { # 禁止以ip方式访问网站
                return 400;
        }
              root /web;
	      index index.html;
    }
    ssl_certificate /xray/tls/server.crt;
    ssl_certificate_key /xray/tls/server.key;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.3;
    ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
    ssl_prefer_server_ciphers on;
}
EOF

fi

systemctl restart nginx

clear
echo -e "安装完成!\n"
echo "trojan://${passwd}@${domain}:$port?security=tls&alpn=h2&type=grpc&serviceName=trojan_grpc&mode=gun#Trojan_gRPC" > ~/node
echo "已经为你生成了节点连接:"
echo
cat ~/node
echo
echo "下次查看节点可执行cat ~/node 命令查看"
echo
echo "访问你的域名试试"
exit
