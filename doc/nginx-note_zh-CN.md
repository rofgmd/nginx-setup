# Nginx 学习笔记

## Nginx 介绍

**nginx [engine x] is an HTTP and reverse proxy server, a mail proxy server, and a generic TCP/UDP proxy server, originally written by [Igor Sysoev](http://sysoev.ru/en/). For a long time, it has been running on many heavily loaded Russian sites including [Yandex](http://www.yandex.ru/), [Mail.Ru](http://mail.ru/), [VK](http://vk.com/), and [Rambler](http://www.rambler.ru/). Here are some of the success stories: [Dropbox](https://blogs.dropbox.com/tech/2017/09/optimizing-web-servers-for-high-throughput-and-low-latency/), [Netflix](https://openconnect.netflix.com/en/software/), [FastMail.FM](http://blog.fastmail.fm/2007/01/04/webimappop-frontend-proxies-changed-to-nginx/).**

### Basic HTTP server features

- Serving static and index files, autoindexing; open file descriptor cache;
- Accelerated reverse proxying with caching; load balancing and fault tolerance;
- Accelerated support with caching of FastCGI, uwsgi, SCGI, and memcached servers; load balancing and fault tolerance;
- Modular architecture. Filters include gzipping, byte ranges, chunked responses, XSLT, SSI, and image transformation filter. Multiple SSI inclusions within a single page can be processed in parallel if they are handled by proxied or FastCGI/uwsgi/SCGI servers;
- SSL and TLS SNI support;
- Support for HTTP/2 with weighted and dependency-based prioritization;
- Support for HTTP/3.

### Other HTTP server features

* Name-based and IP-based [virtual servers](https://nginx.org/en/docs/http/request_processing.html);
* [Keep-alive](https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_timeout) and pipelined connections support;
* [Access log formats](https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format), [buffered log writing](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log), [fast log rotation](https://nginx.org/en/docs/control.html#logs), and [syslog logging](https://nginx.org/en/docs/syslog.html);
* 3xx-5xx error codes [redirection](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page);
* The rewrite module: [URI changing using regular expressions](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html);
* [Executing different functions](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#if) depending on the [client address](https://nginx.org/en/docs/http/ngx_http_geo_module.html);
* Access control based on [client IP address](https://nginx.org/en/docs/http/ngx_http_access_module.html), [by password (HTTP Basic authentication)](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html) and by the [result of subrequest](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html);
* Validation of [HTTP referer](https://nginx.org/en/docs/http/ngx_http_referer_module.html);
* The [PUT, DELETE, MKCOL, COPY, and MOVE](https://nginx.org/en/docs/http/ngx_http_dav_module.html) methods;
* [FLV](https://nginx.org/en/docs/http/ngx_http_flv_module.html) and [MP4](https://nginx.org/en/docs/http/ngx_http_mp4_module.html) streaming;
* [Response rate limiting](https://nginx.org/en/docs/http/ngx_http_core_module.html#limit_rate);
* Limiting the number of simultaneous [connections](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html) or [requests](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) coming from one address;
* [IP-based geolocation](https://nginx.org/en/docs/http/ngx_http_geoip_module.html);
* [A/B testing](https://nginx.org/en/docs/http/ngx_http_split_clients_module.html);
* [Request mirroring](https://nginx.org/en/docs/http/ngx_http_mirror_module.html);
* Embedded [Perl](https://nginx.org/en/docs/http/ngx_http_perl_module.html);
* [njs](https://nginx.org/en/docs/njs/index.html) scripting language.

### TCP/UDP proxy server features

* [Generic proxying](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html) of TCP and UDP;
* [SSL](https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html) and TLS [SNI](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html) support for TCP;
* [Load balancing and fault tolerance](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html);
* Access control based on [client address](https://nginx.org/en/docs/stream/ngx_stream_access_module.html);
* Executing different functions depending on the [client address](https://nginx.org/en/docs/stream/ngx_stream_geo_module.html);
* Limiting the number of simultaneous [connections](https://nginx.org/en/docs/stream/ngx_stream_limit_conn_module.html) coming from one address;
* [Access log formats](https://nginx.org/en/docs/stream/ngx_stream_log_module.html#log_format), [buffered log writing](https://nginx.org/en/docs/stream/ngx_stream_log_module.html#access_log), [fast log rotation](https://nginx.org/en/docs/control.html#logs), and [syslog logging](https://nginx.org/en/docs/syslog.html);
* [IP-based geolocation](https://nginx.org/en/docs/stream/ngx_stream_geoip_module.html);
* [A/B testing](https://nginx.org/en/docs/stream/ngx_stream_split_clients_module.html);
* [njs](https://nginx.org/en/docs/njs/index.html) scripting language.

### Architecture and scalability

* One master and several worker processes; worker processes run under an unprivileged user;
* [Flexible configuration](https://nginx.org/en/docs/example.html);
* [Reconfiguration](https://nginx.org/en/docs/control.html#reconfiguration) and [upgrade of an executable](https://nginx.org/en/docs/control.html#upgrade) without interruption of the client servicing;
* [Support](https://nginx.org/en/docs/events.html) for kqueue (FreeBSD 4.1+), epoll (Linux 2.6+), /dev/poll (Solaris 7 11/99+), event ports (Solaris 10), select, and poll;
* The support of the various kqueue features including EV_CLEAR, EV_DISABLE (to temporarily disable events), NOTE_LOWAT, EV_EOF, number of available data, error codes;
* The support of various epoll features including EPOLLRDHUP (Linux 2.6.17+, glibc 2.8+) and EPOLLEXCLUSIVE (Linux 4.5+, glibc 2.24+);
* sendfile (FreeBSD 3.1+, Linux 2.2+, macOS 10.5+), sendfile64 (Linux 2.4.21+), and sendfilev (Solaris 8 7/01+) support;
* [File AIO](https://nginx.org/en/docs/http/ngx_http_core_module.html#aio) (FreeBSD 4.3+, Linux 2.6.22+);
* [DIRECTIO](https://nginx.org/en/docs/http/ngx_http_core_module.html#directio) (FreeBSD 4.4+, Linux 2.4+, Solaris 2.6+, macOS);
* Accept-filters (FreeBSD 4.1+, NetBSD 5.0+) and TCP_DEFER_ACCEPT (Linux 2.4+) [support](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen);
* 10,000 inactive HTTP keep-alive connections take about 2.5M memory;
* Data copy operations are kept to a minimum.

## Nginx 安装、启动

### Macos

#### 安装

```bash
brew install nginx
```

#### 启动

```bash
brew services start nginx
```

### Linux-Debian

#### 安装

```bash
sudo apt install nginx
```

#### 启动

```bash
systemctl start nginx

lima@lima-default:~/entrytask-webhock$ sudo systemctl start nginx
lima@lima-default:~/entrytask-webhock$ ps aux | grep nginx
root       24483  0.0  0.0  11156  1716 ?        Ss   09:50   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data   24484  0.0  0.1  12880  4148 ?        S    09:50   0:00 nginx: worker process
www-data   24485  0.0  0.1  12880  4404 ?        S    09:50   0:00 nginx: worker process
www-data   24486  0.0  0.1  12880  4276 ?        S    09:50   0:00 nginx: worker process
www-data   24487  0.0  0.1  12880  4148 ?        S    09:50   0:00 nginx: worker process
lima       24491  0.0  0.0   7076  2048 pts/0    S+   09:50   0:00 grep --color=auto nginx
```

### 验证安装是否成功（通过查看nginx版本）

```bash
lima@lima-default:/etc/nginx$ nginx -v
nginx version: nginx/1.24.0 (Ubuntu)
lima@lima-default:/etc/nginx$ nginx -V
nginx version: nginx/1.24.0 (Ubuntu)
built with OpenSSL 3.0.10 1 Aug 2023 (running with OpenSSL 3.0.13 30 Jan 2024)
TLS SNI support enabled
configure arguments: --with-cc-opt='-g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -ffile-prefix-map=/build/nginx-uqDps2/nginx-1.24.0=. -flto=auto -ffat-lto-objects -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -fdebug-prefix-map=/build/nginx-uqDps2/nginx-1.24.0=/usr/src/nginx-1.24.0-2ubuntu7 -fPIC -Wdate-time -D_FORTIFY_SOURCE=3' --with-ld-opt='-Wl,-Bsymbolic-functions -flto=auto -ffat-lto-objects -Wl,-z,relro -Wl,-z,now -fPIC' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=stderr --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-compat --with-debug --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_v2_module --with-http_dav_module --with-http_slice_module --with-threads --with-http_addition_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_secure_link_module --with-http_sub_module --with-mail_ssl_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-stream_realip_module --with-http_geoip_module=dynamic --with-http_image_filter_module=dynamic --with-http_perl_module=dynamic --with-http_xslt_module=dynamic --with-mail=dynamic --with-stream=dynamic --with-stream_geoip_module=dynamic
```

## Starting, Stopping, and Reloading Configuration

To start nginx, run the executable file. Once nginx is started, it can be controlled by invoking the executable with the `-s` parameter. Use the following syntax:

> ```bash
> nginx -s signal
> ```

Where *signal* may be one of the following:

* `stop` — fast shutdown
* `quit` — graceful shutdown
* `reload` — reloading the configuration file
* `reopen` — reopening the log files

### 启动nginx

#### 启动

```bash
systemctl start nginx

lima@lima-default:~/entrytask-webhock$ sudo systemctl start nginx
lima@lima-default:~/entrytask-webhock$ ps aux | grep nginx
root       24483  0.0  0.0  11156  1716 ?        Ss   09:50   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data   24484  0.0  0.1  12880  4148 ?        S    09:50   0:00 nginx: worker process
www-data   24485  0.0  0.1  12880  4404 ?        S    09:50   0:00 nginx: worker process
www-data   24486  0.0  0.1  12880  4276 ?        S    09:50   0:00 nginx: worker process
www-data   24487  0.0  0.1  12880  4148 ?        S    09:50   0:00 nginx: worker process
lima       24491  0.0  0.0   7076  2048 pts/0    S+   09:50   0:00 grep --color=auto nginx
```

#### 查看nginx是否启动成功

在浏览器中输入localhost，就可以看到默认页面

也可以用curl命令去查看

```bash
kaihang.weng@C02FRP54MD6M ~ % curl http://localhost:80
```

```html
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

### quit

```bash
lima@lima-default:~/entrytask-webhock$ nginx -s quit
2024/07/17 09:49:28 [warn] 24427#24427: the "user" directive makes sense only if the master process runs with super-user privileges, ignored in /etc/nginx/nginx.conf:1
2024/07/17 09:49:28 [notice] 24427#24427: signal process started
2024/07/17 09:49:28 [alert] 24427#24427: kill(24031, 3) failed (1: Operation not permitted)
lima@lima-default:~/entrytask-webhock$ ps aux | grep nginx
root       24031  0.0  0.0  11156  1716 ?        Ss   09:35   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data   24032  0.0  0.1  12880  4404 ?        S    09:35   0:00 nginx: worker process
www-data   24033  0.0  0.1  12880  4404 ?        S    09:35   0:00 nginx: worker process
www-data   24034  0.0  0.1  12880  4404 ?        S    09:35   0:00 nginx: worker process
www-data   24035  0.0  0.1  12880  4276 ?        S    09:35   0:00 nginx: worker process
lima       24432  0.0  0.0   7076  2048 pts/0    S+   09:49   0:00 grep --color=auto nginx
lima@lima-default:~/entrytask-webhock$ sudo nginx -s quit
2024/07/17 09:49:45 [notice] 24438#24438: signal process started
lima@lima-default:~/entrytask-webhock$ ps aux | grep nginx
lima       24444  0.0  0.0   7076  2048 pts/0    S+   09:49   0:00 grep --color=auto nginx
# 或者用kill也可以
lima@lima-default:~$ ps ax | grep nginx
  24483 ?        Ss     0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
  24484 ?        S      0:00 nginx: worker process
  24485 ?        S      0:00 nginx: worker process
  24486 ?        S      0:00 nginx: worker process
  24487 ?        S      0:00 nginx: worker process
  24603 pts/0    S+     0:00 grep --color=auto nginx
lima@lima-default:~$ kill -s QUIT 24483
bash: kill: (24483) - Operation not permitted
lima@lima-default:~$ sudo kill -s QUIT 24483
lima@lima-default:~$ ps ax | grep nginx
  24622 pts/0    S+     0:00 grep --color=auto nginx
```

## Nginx配置文档

配置文档：/etc/nginx/nginx.conf

```nginx
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;

	##
	# Gzip Settings
	##

	gzip on;

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}


#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
#
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
```

### Configuration File’s Structure

nginx consists of modules which are controlled by directives specified in the configuration file. Directives are divided into simple directives and block directives. A simple directive consists of the name and parameters separated by spaces and ends with a semicolon (`;`). A block directive has the same structure as a simple directive, but instead of the semicolon it ends with a set of additional instructions surrounded by braces (`{` and `}`). If a block directive can have other directives inside braces, it is called a context (examples: [events](https://nginx.org/en/docs/ngx_core_module.html#events), [http](https://nginx.org/en/docs/http/ngx_http_core_module.html#http), [server](https://nginx.org/en/docs/http/ngx_http_core_module.html#server), and [location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location)).

Directives placed in the configuration file outside of any contexts are considered to be in the [main](https://nginx.org/en/docs/ngx_core_module.html) context. The `events` and `http` directives reside in the `main` context, `server` in `http`, and `location` in `server`.

The rest of a line after the `#` sign is considered a comment.

> nginx 由由配置文件中指定的指令控制的模块组成。**指令分为简单指令和块指令。简单的指令由名称和参数组成，名称和参数之间用空格分隔，并以分号 (;) 结尾。块指令具有与简单指令相同的结构，但它不是以分号结尾，而是以一组用大括号（{ 和 }）括起来的附加指令结尾。如果块指令可以在大括号内包含其他指令，则称为上下文（例如：事件、http、服务器和位置）。**
>
> 放置在任何上下文之外的配置文件中的指令都被视为位于主上下文中。事件和http指令驻留在主上下文中，服务器驻留在http中，位置驻留在server中。
>
> \**#** **符号之后的其余行被视为注释。**

### Nginx默认启动分析

查看默认页面

```bash
lima@lima-default:/etc/nginx/sites-available$ cat default 
```

可以看到默认配置

```nginx
##
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# https://www.nginx.com/resources/wiki/start/
# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
# https://wiki.debian.org/Nginx/DirectoryStructure
#
# In most cases, administrators will remove this file from sites-enabled/ and
# leave it as reference inside of sites-available where it will continue to be
# updated by the nginx packaging team.
#
# This file will automatically load configuration files provided by other
# applications, such as Drupal or Wordpress. These applications will be made
# available underneath a path with that package name, such as /drupal8.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

# Default server configuration
#
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	# SSL configuration
	#
	# listen 443 ssl default_server;
	# listen [::]:443 ssl default_server;
	#
	# Note: You should disable gzip for SSL traffic.
	# See: https://bugs.debian.org/773332
	#
	# Read up on ssl_ciphers to ensure a secure configuration.
	# See: https://bugs.debian.org/765782
	#
	# Self signed certs generated by the ssl-cert package
	# Don't use them in a production server!
	#
	# include snippets/snakeoil.conf;

	root /var/www/html;

	# Add index.php to the list if you are using PHP
	index index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
	}

	# pass PHP scripts to FastCGI server
	#
	#location ~ \.php$ {
	#	include snippets/fastcgi-php.conf;
	#
	#	# With php-fpm (or other unix sockets):
	#	fastcgi_pass unix:/run/php/php7.4-fpm.sock;
	#	# With php-cgi (or other tcp sockets):
	#	fastcgi_pass 127.0.0.1:9000;
	#}

	# deny access to .htaccess files, if Apache's document root
	# concurs with nginx's one
	#
	#location ~ /\.ht {
	#	deny all;
	#}
}


# Virtual Host configuration for example.com
#
# You can move that to a different file under sites-available/ and symlink that
# to sites-enabled/ to enable it.
#
#server {
#	listen 80;
#	listen [::]:80;
#
#	server_name example.com;
#
#	root /var/www/example.com;
#	index index.html;
#
#	location / {
#		try_files $uri $uri/ =404;
#	}
#}
```

### 查看nginx启动配置

使用`-t`命令进行查看

```bash
kaihang.weng@C02FRP54MD6M nginx % nginx -t
nginx: the configuration file /usr/local/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /usr/local/etc/nginx/nginx.conf test is successful
```

### Serving Static Content

An important web server task is serving out files (such as images or static HTML pages). You will implement an example where, depending on the request, files will be served from different local directories: `/data/www` (which may contain HTML files) and `/data/images` (containing images). This will require editing of the configuration file and setting up of a [server](https://nginx.org/en/docs/http/ngx_http_core_module.html#server) block inside the [http](https://nginx.org/en/docs/http/ngx_http_core_module.html#http) block with two [location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location) blocks.

First, create the `/data/www` directory and put an `index.html` file with any text content into it and create the `/data/images` directory and place some images in it.

Next, open the configuration file. The default configuration file already includes several examples of the `server` block, mostly commented out. For now comment out all such blocks and start a new `server` block:

在 `/etc/nginx/sites-available/default`是默认页面启动配置

```nginx
# Default server configuration
#
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	root /var/www/html;

	# Add index.php to the list if you are using PHP
	index index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
	}
}
```

### 自己配置Nginx静态页面

首先，在 `/etc/nginx/nginx.conf` 的HTTP模块中，看到这句

```nginx
include /etc/nginx/conf.d/*.conf;
```

所以就包含了 `/etc/nginx/conf.d/`下面的所有conf文件

不过Macos配置不太一样，nginx在`/usr/local/etc/nginx/`下面

创建一个`/usr/local/etc/nginx/nginx_costumize.conf`

```nginx
# practice for nginx conf

worker_processes 2;

events{
    worker_connections 1024;
}

http{
    include mime.types;
    default_type application/octet-stream;

    sendfile on;
    keepalive_timeout 65;

    server{
        listen 80;
        server_name localhost;

        location / {
            root /Users/kaihang.weng/nginx-test/www/html;
            index index.html;
        }

    }
}
```

然后测试一下，用`-t`命令测试

```bash
kaihang.weng@C02FRP54MD6M html % nginx -t -c /usr/local/etc/nginx/nginx_costumize.conf
nginx: the configuration file /usr/local/etc/nginx/nginx_costumize.conf syntax is ok
nginx: configuration file /usr/local/etc/nginx/nginx_costumize.conf test is successful
```

