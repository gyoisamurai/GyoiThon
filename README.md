![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/asia/2018.svg?sanitize=true)

# **GyoiThon** ![gyoithon's logo](./img/gyoi_logo.png)  
**Next generation penetration test tool**

---

Japanese page is [here](https://github.com/gyoisamurai/GyoiThon/wiki).

### Presentation
 * January 25th,2018:[JANOG41](https://www.janog.gr.jp/meeting/janog41/program/sp5sts)  
 * March 23th,2018:[Black Hat ASIA 2018 Arsenal](https://www.blackhat.com/asia-18/arsenal/schedule/index.html#gyoithon-9651)  
 * August 12th,2018:[DEFCON26 DemoLabs](https://www.defcon.org/html/defcon-26/dc-26-demolabs.html#GyoiThon)  
 * November 3rd,2018:[AV TOKYO 2018 HIVE](http://ja.avtokyo.org/avtokyo2018/event)

## Overview
GyoiThon is **Intelligence Gathering tool** for Web Server.  

GyoiThon execute **remote access** to target Web server and **identifies product operated on the server** such as CMS, Web server software, Framework, Programming Language etc,. And, it can **execute exploit modules** to identified products using Metasploit. GyoiThon **fully automatically execute** above action.  
GyoiThon's main features are following.  

 * Remote access/Fully automatic  
 GyoiThon can **fully automatically** gather the information of target Web server using only **remote access**. You only execute GyoiThon once for your operation.  

 * Non-destructive test  
 GyoiThon can gather information of target Web server using **only normally access**.  
 But, when you use a part of option, GyoiThon execute abnormally access such as sending exploit modules.  

 * Gathering various information  
 GyoiThon has various intelligence gathering engines such as Web crawler, Google Custom Search API, Censys, explorer of default contents, examination of cloud services etc,. By analyze gathered information using **strings pattern matching** and **machine learning**, GyoiThon can identify **product/version/CVE number** operated on the target web server, **unnecceary html comments**/**debug messages**, **login page** etc,.  

 * Examination of real vulnerability  
 GyoiThon can execute exploit modules to identified products using Metasploit.  
 As a result, it can **examine real vulnerability of target web server**.  

![Overview](https://github.com/gyoisamurai/GyoiThon/raw/master/img/overview.png)

| Note |
|:-----|
| If you are interested, please use them in an environment under your control and at your own risk. |

## Installation
1. git clone GyoiThon's repository.  
```
root@kali:~# git clone https://github.com/gyoisamurai/GyoiThon.git
```

2. Get python3-pip.  
```
root@kali:~# apt-get update
root@kali:~# apt-get install python3-pip
```

3. install required python packages.  
```
root@kali:~# cd GyoiThon
root@kali:~/GyoiThon# pip3 install -r requirements.txt
```

4. Edit config.ini of GyoiThon.
You have to edit your `config.ini`.  
More information is Usage.  

## Usage
By using [default mode] without option and [combination of several options], GyoiThon can gather various information of target web server.  

```
usage:
    gyoithon.py [-s] [-m] [-g] [-e] [-c] [-p] [-l <log_path>]
    gyoithon.py -h | --help
options:
    -s   Optional : Examine cloud service.
    -m   Optional : Analyze HTTP response for identify product/version using Machine Learning.
    -g   Optional : Google Custom Search for identify product/version.
    -e   Optional : Explore default path of product.
    -c   Optional : Discover open ports and wrong ssl server certification using Censys.
    -p   Optional : Execute exploit module using Metasploit.
    -l   Optional : Analyze log based HTTP response for identify product/version.
    -h --help     Show this help message and exit.
```

### Preparation.  
1. Edit target file `host.txt`.  
You have to write target web server to the `host.txt`.  
Writting format is `protocol FQDN(or IP address) Port Crawling_root_path`.  

* Example.  
```
https gyoithon.example.com 443 /
```

If you want to indicate multiple target information, you have to write below.  

```
https gyoithon.example.com 443 /
http 192.168.220.129 80 /vicnum/
https www.example.com 443 /catalog/
```

| Note |
|:-----|
| You insert `/` at the beginning and end of Root Path. |

2. Edit configuration file `config.ini`.  
Parameters to be changed by the user are defined in the setting file `config.ini`.  
If you want to change parameters, edit `config.ini`.  
Detail of `config.ini` is [here](https://github.com/gyoisamurai/GyoiThon/wiki/Configure).  

### Execution of GyoiThon.  

#### Step.1 Run GyoiThon
You execute GyoiThon following command.  

```
root@kali:~/GyoiThon# python3 gyoithon.py
```

#### Step.2 Check scan report
Please check scan report using any web browser.  

```
root@kali:~/GyoiThon# cd classifier4gyoithon/report/
root@kali:~/GyoiThon/classifier4gyoithon/report# firefox gyoithon_report.html
```

## Tips
#### 1. How to add string matching patterns.  
`signatures` path includes four files corresponding to each product categories.  

```
local@client:~$ ls "gyoithon root path"/signatures/
signature_cms.txt
signature_framework.txt
signature_os.txt
signature_web.txt
```

 * `signature_cms.txt`  
 It includes string matching patterns of CMS.  
 * `signature_framework.txt`  
 It includes string matching patterns of FrameWork.  
 * `signature_os.txt`  
 It includes string matching patterns of Operating System.  
 * `signature_web.txt`  
 It includes string matching patterns of Web server software.  

If you want to add new string matching patterns, you add new string matching patterns at last line in each file.  

ex) How to add new string matching pattern of CMS at `signature_cms.txt`.  
```
tikiwiki@(Powered by TikiWiki)
wordpress@<.*=(.*/wp-).*/.*>
wordpress@(<meta name="generator" content="WordPress).*>

...snip...

typo@.*(href="fileadmin/templates/).*>
typo@(<meta name="generator" content="TYPO3 CMS).*>
"new product name"@"regex pattern"
[EOF]
```

 |Note|
 |:---|
 |Above new product name must be a name that Metasploit can identify. And you have to separate new product name and regex pattern using `@`.|


#### 2. How to add learning data.  
`signatures` path includes four files corresponding to each product categories.  

```
local@client:~$ ls "gyoithon root path"/classifier4gyoithon/train_data/
train_cms_in.txt
train_framework_in.txt
train_os_in.txt
train_web_in.txt
```

 * `train_cms_in.txt`  
 It includes learning data of CMS.  
 * `train_framework_in.txt`  
 It includes learning data of FrameWork.  
 * `train_os_in.txt`  
 It includes learning data of Operating System.  
 * `train_web_in.txt`  
 It includes learning data of Web server software.  

If you want to add new learning data, you add learning data at last line in each file.  

ex) How to add new learning data of CMS at `train_cms_in.txt`.  
```
joomla@(Set-Cookie: [a-z0-9]{32}=.*);
joomla@(Set-Cookie: .*=[a-z0-9]{26,32});

...snip...

xoops@(xoops\.js)
xoops@(xoops\.css)
"new product name"@"regex pattern"
[EOF]
```

 |Note|
 |:---|
 |Above new product name must be a name that Metasploit can identify. And you have to separate new product name and regex pattern using `@`.|

In addition, since GyoiThon retrains with new training data, you have to delete old training data (`*.pkl`).  

```
local@client:~$ ls "gyoithon root path"/classifier4gyoithon/trained_data/
train_cms_out.pkl
train_framework_out.pkl
train_web_out.pkl
local@client:~$ rm "gyoithon root path"/classifier4gyoithon/trained_data/*.pkl
```

#### 3. How to change "Exploit module's option".
When GyoiThon exploits, it uses **default value** of Exploit module options.  
If you want to change option values, please input any value to `"user_specify"` in [`exploit_tree.json`](https://raw.githubusercontent.com/gyoisamurai/GyoiThon/master/classifier4gyoithon/data/exploit_tree.json) as following.

```

"unix/webapp/joomla_media_upload_exec": {
    "targets": {
        "0": [
            "generic/custom",
            "generic/shell_bind_tcp",
            "generic/shell_reverse_tcp",

...snip...

        "TARGETURI": {
            "type": "string",
            "required": true,
            "advanced": false,
            "evasion": false,
            "desc": "The base path to Joomla",
            "default": "/joomla",
            "user_specify": "/my_original_dir/"
        },
```
Above example is to change value of `TARGETURI` option in exploit module "`exploit/unix/webapp/joomla_media_upload_exec`" to "`/my_original_dir/`" from "`/joomla`".  

#### 4. How to use each instance.
##### `GyoiClassifier.py`  
You can use the log "webconf.csv" gathered by GyoiThon or the log gathered by GyoiClassifier to identify products operated on the target server. Then, the product is identified using machine learning.  

 * Usage (using `webconf.csv`)  
 GyoiClassifier identifies product name using `webconf.csv`.  

 ```
 local@client:~$ python GyoiClassifier.py -h
 GyoiClassifier.py
 Usage:
     GyoiClassifier.py (-t <ip_addr> | --target <ip_addr>) (-p <port> | --port <port>) (-v <vhost> | --vhost <vhost>) [(-u <url> | --url <url>)]
     GyoiClassifier.py -h | --help
 Options:
     -t --target   Require  : IP address of target server.
     -p --port     Require  : Port number of target server.
     -v --vhost    Require  : Virtual Host of target server.
     -u --url      Optional : Full URL for direct access.
     -h --help     Optional : Show this screen and exit.

 local@client:~$ python GyoiClassifier.py -t 192.168.220.148 -p 80 -v 192.168.220.148
 
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 　　███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗███╗   ██╗███████╗
 　　████╗ ████║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔════╝
 　　██╔████╔██║███████║██║     ███████║██║██╔██╗ ██║█████╗
 　　██║╚██╔╝██║██╔══██║██║     ██╔══██║██║██║╚██╗██║██╔══╝
 　　██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║██║ ╚████║███████╗
 　　╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
 
 　██╗     ███████╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗
 　██║     ██╔════╝██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝
 　██║     █████╗  ███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 　██║     ██╔══╝  ██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
 　███████╗███████╗██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
 　╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
　 　   __      _   _      _   _                 _        _
　 　  / /  ___| |_( )__  | |_| |__   ___  _ __ | |_ __ _| | __
　 　 / /  / _ \ __|/ __| | __| '_ \ / _ \| '_ \| __/ _` | |/ /
　 　/ /__|  __/ |_ \__ \ | |_| | | | (_) | | | | || (_| |   <
　 　\____/\___|\__||___/  \__|_| |_|\___/|_| |_|\__\__,_|_|\_
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 by GyoiClassifier.py
 
 ------------------------------------------
 target     : 192.168.220.148(192.168.220.148):80
 target log : "gyoithon root path"../gyoithon\get_192.168.220.148_80_ip.log
 
 [+] judge :
 [-] category : web server
     product  : unknown
     too low maximum probability.
 [-] category : framework
     product  : unknown
     too low maximum probability.
 [-] category : cms
     -----
     ranking 1
     product     : heartcore
     probability : 6.8966 %
     reason      : [['Set-Cookie: PHPSESSID=44ec9b66c633a7abc374e5f9a4ad4be3', 'Set-Cookie:  PHPSESSID=b1f9a2c2be74f3b3507d5cbb8ea78c75']]
     -----
     ranking 2
     product     : oscommerce
     probability : 6.8966 %
     reason      : [['Set-Cookie: PHPSESSID=44ec9b66c633a7abc374e5f9a4ad4be3', 'Set-Cookie: PHPSESSID=b1f9a2c2be74f3b3507d5cbb8ea78c75']]
     -----
     ranking 3
     product     : joomla
     probability : 6.6667 %
     reason      : [['Set-Cookie: PHPSESSID=44ec9b66c633a7abc374e5f9a4ad4be3', 'Set-Cookie: PHPSESSID=b1f9a2c2be74f3b3507d5cbb8ea78c75']]
 ------------------------------------------
 
 [+] done GyoiClassifier.py
 GyoiClassifier.py finish!!
 ```

 * Usage (using self-gathered log)  
 GyoiClassifier identifies product name using self-gathered log.  
 
 ```
 local@client:~$ python GyoiClassifier.py -t 192.168.220.129 -p 80 -v www.example.com -u http://www.example.com/
 
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 　　███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗███╗   ██╗███████╗
 　　████╗ ████║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔════╝
 　　██╔████╔██║███████║██║     ███████║██║██╔██╗ ██║█████╗
 　　██║╚██╔╝██║██╔══██║██║     ██╔══██║██║██║╚██╗██║██╔══╝
 　　██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║██║ ╚████║███████╗
 　　╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝ 
 
 　██╗     ███████╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗ 
 　██║     ██╔════╝██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝ 
 　██║     █████╗  ███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 　██║     ██╔══╝  ██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
 　███████╗███████╗██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
 　╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
 　　   __      _   _      _   _                 _        _    
 　　  / /  ___| |_( )__  | |_| |__   ___  _ __ | |_ __ _| | __
 　　 / /  / _ \ __|/ __| | __| '_ \ / _ \| '_ \| __/ _` | |/ /
 　　/ /__|  __/ |_ \__ \ | |_| | | | (_) | | | | || (_| |   < 
 　　\____/\___|\__||___/  \__|_| |_|\___/|_| |_|\__\__,_|_|\_
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 by GyoiClassifier.py
 
 ------------------------------------------
 target     : http://www.example.com/
 target log : not use
 
 [+] judge :
 [-] category : web server
     product  : unknown
     too low maximum probability.
 [-] category : framework
     -----
     ranking 1
     product     : php
     probability : 66.6667 %
     reason      : [['Set-Cookie: f00e68432b68050dee9abe33c389831e=a3daf0eba60a5f11c95e4563c4eccebe']]
 [-] category : cms
     -----
     ranking 1
     product     : joomla
     probability : 13.3333 %
     reason      : [['Set-Cookie: f00e68432b68050dee9abe33c389831e=a3daf0eba60a5f11c95e4563c4eccebe; path=/'], ['Set-Cookie: f00e68432b68050dee9abe33c389831e=a3daf0eba60a5f11c95e4563c4eccebe'], ['Joomla!']]
     -----
     ranking 2
     product     : heartcore
     probability : 6.8966 %
     reason      : [['Set-Cookie: f00e68432b68050dee9abe33c389831e=a3daf0eba60a5f11c95e4563c4eccebe']]
 ------------------------------------------
 
 [+] done GyoiClassifier.py
 GyoiClassifier.py finish!!
 ```

|option|required|description|
|:---|:---|:---|
|-t, --target|yes|IP address of target server.|
|-p, --port|yes|Target port number.|
|-v, --vhost|yes|Virtual host of target server. If target server hasn't virtual host, you indicate IP address.|
|-u, --url|no|URL of target server. If you want to gather newly logs of any server, indicate url of target server.|

##### `GyoiExploit.py`
You can execute exploits thoroughly using all combinations of "Exploit module", "Target" and "Payload" of Metasploit corresponding to user's indicated product name and port number.

 * Usage 
 ```
 local@client:~$ python GyoiExploit.py -h
 GyoiExploit.py
 Usage:
     GyoiExploit.py (-t <ip_addr> | --target <ip_addr>) (-p <port> | --port <port>) (-s <service> | --service <service>)
     GyoiExploit.py -h | --help
 
 Options:
     -t --target   Require  : IP address of target server.
     -p --port     Require  : Port number of target server.
     -s --service  Require  : Service name (product name).
     -h --help     Optional : Show this screen and exit.

 local@client:~$ python GyoiExploit.py -t 192.168.220.145 -p 3306 -s mysql

 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗██╗██╗
   ██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██║██║
   █████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   ██║██║
   ██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   ╚═╝╚═╝
   ███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   ██╗██╗
   ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝╚═╝
 　   __      _   _      _   _                 _        _
 　  / /  ___| |_( )__  | |_| |__   ___  _ __ | |_ __ _| | __
 　 / /  / _ \ __|/ __| | __| '_ \ / _ \| '_ \| __/ _` | |/ /
 　/ /__|  __/ |_ \__ \ | |_| | | | (_) | | | | || (_| |   <
 　\____/\___|\__||___/  \__|_| |_|\___/|_| |_|\__\__,_|_|\_
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 by GyoiExploit.py
 
 [+] Get exploit list.
 [*] Loading exploit list from local file: C:\Users\i.takaesu\Documents\GitHub\GyoiThon\classifier4gyoithon\data\exploit_list.csv
 [+] Get exploit tree.
 [*] Loading exploit tree from local file: C:\Users\i.takaesu\Documents\GitHub\GyoiThon\classifier4gyoithon\data\exploit_tree.json
 [*] exploit/linux/mysql/mysql_yassl_getname, target: 0, payload: generic/custom, result: failure
 [*] exploit/linux/mysql/mysql_yassl_getname, target: 0, payload: generic/debug_trap, result: failure
 [*] exploit/linux/mysql/mysql_yassl_getname, target: 0, payload: generic/shell_bind_tcp, result: bingo!!
 [*] exploit/linux/mysql/mysql_yassl_getname, target: 0, payload: generic/shell_reverse_tcp, result: failure
 [*] exploit/linux/mysql/mysql_yassl_getname, target: 0, payload: generic/tight_loop, result: failure 
 
 ...snip...
 
 [*] exploit/linux/mysql/mysql_yassl_getname, target: 1, payload: linux/x86/shell_bind_tcp_random_port, result: failure
 [*] exploit/linux/mysql/mysql_yassl_getname, target: 1, payload: linux/x86/shell_reverse_tcp, result: failure
 [*] exploit/linux/mysql/mysql_yassl_hello, target: 0, payload: generic/custom, result: failure
 [*] exploit/linux/mysql/mysql_yassl_hello, target: 0, payload: generic/debug_trap, result: bingo!!
 [*] exploit/linux/mysql/mysql_yassl_hello, target: 0, payload: generic/shell_bind_tcp, result: failure
 
 ...snip...
```

|option|required|description|
|:---|:---|:---|
|-t, --target|yes|IP address of target server.|
|-p, --port|yes|Target port number.|
|-s, --service|yes|Target service name identifiable by Metasploit.|

If you want to change "exploit module" options, please refer this section \[3. How to change "Exploit module's option"].  

## Operation check environment
 * Kali Linux 2018.2 (for Metasploit)
   * Memory: 8.0GB
   * Metasploit Framework 4.16.48-dev
 * ubuntu 16.04 LTS (Host OS)
   * CPU: Intel(R) Core(TM) i5-5200U 2.20GHz
   * Memory: 8.0GB
   * Python 3.6.1（Anaconda3）
   * docopt==0.6.2
   * jinja2==2.10
   * msgpack-python==0.4.8
   * pandas==0.23.4
   * urllib3==1.23
   * Scrapy==1.5.1

## Licence
[Apache License 2.0](https://github.com/gyoisamurai/GyoiThon/blob/master/LICENSE)

## SNS
 * [Slack](https://gyoithon.slack.com)

## Contact us
 gyoiler3@gmail.com  

 * [Masafumi Masuya](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#masafumi-masuya-36855)  
 [https://twitter.com/gyoizamurai](https://twitter.com/gyoizamurai)
 * [Toshitsugu Yoneyama](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#toshitsugu-yoneyama-36864)  
 [https://twitter.com/yoneyoneyo](https://twitter.com/yoneyoneyo)
 * [Isao Takaesu](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#isao-takaesu-33544)  
 [https://twitter.com/bbr_bbq](https://twitter.com/bbr_bbq)
