![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/asia/2018.svg?sanitize=true)

# **GyoiThon** ![gyoithon's logo](./img/gyoi_logo.png)  
**Next generation penetration test tool**

---

Japanese page is [here](https://github.com/gyoisamurai/GyoiThon/wiki).

## Presentation
 * January 25th,2018:[JANOG41](https://www.janog.gr.jp/meeting/janog41/program/sp5sts)  
 * March 23th,2018:[Black Hat ASIA 2018 Arsenal](https://www.blackhat.com/asia-18/arsenal/schedule/index.html#gyoithon-9651)  
 * August 12th,2018:[DEFCON26 DemoLabs](https://www.defcon.org/html/defcon-26/dc-26-demolabs.html#GyoiThon)  
 * November 3rd,2018:[AV TOKYO 2018 HIVE](http://ja.avtokyo.org/avtokyo2018/event)

## Documents
 * [Installation](https://github.com/gyoisamurai/GyoiThon/blob/master/README.md#Installation)  
 * [Usage](https://github.com/gyoisamurai/GyoiThon/blob/master/README.md#Usage)  
 * [Tips](https://github.com/gyoisamurai/GyoiThon/blob/master/README.md#Tips)  
 * [Demonstration](https://www.youtube.com/watch?v=cFgyBJuYQQ4) (Youtube)  

## Slack
 * [https://gyoithon.slack.com](https://gyoithon.slack.com)  
 [Let's join GyoiThon Slack!!](https://docs.google.com/forms/d/e/1FAIpQLSeuT-HNF-geek1IM3qBWViTVJbLUr3GZR2Hzuow30734X70gw/viewform)  

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
| If you are interested, **please use them in an environment under your control and at your own risk**. |

## <a name='Installation'>Installation</a>
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

## <a name='Usage'>Usage</a>
By using [default mode](https://github.com/gyoisamurai/GyoiThon/blob/master/README.md#default_mode) without option and [combination of several options](https://github.com/gyoisamurai/GyoiThon/blob/master/README.md#complex_mode), GyoiThon can gather various information of target web server.  

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
#### <a name='default_mode'>1. Default mode.</a>  
```
root@kali:~/GyoiThon# python3 gyoithon.py
```

The default mode gathers following minimum information.  

 1. Gathering of HTTP responses by Web crawling.  
 2. Identification of product/version using string pattern matching.  
 3. Examination of CVE number (from NVD) for identified products.  
 4. Examination of unneccesary HTML/JavaScript comments.  
 5. Examination of unneccesary debug messages.  
 6. Examination of login pages.  

GyoiThon uses `Scrapy` that Python's library.  
By change the parameters in `config.ini`, you can change setting of Scrapy.  

|Category|Parameter|Description|
|:----|:----|:----|
|Spider|depth_limit|Maximum depth of crawling. Default value is `2` layer. |
||delay_time|Delay time of crawling. Default value is `3` (sec). |
||time_out|Spider close option. Timeout of crawling. Default value is `600` (sec). |
||item_count|Spider close option. Maximum items. Default value is `300`. |
||page_count|Spider close option. Maximum items per page. Default value is `0` (no limit). |
||error_count|Spider close option. Maximum errors. Default value is `0` (no limit). |

#### 2. Examination of cloud services mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -s
```

By add `-s` option, GyoiThon identifies target web server uses cloud service or not  in addition to default mode.  
Before execution, you must change the below parameter of `config.ini`.  

|Category|Parameter|Description|
|:----|:----|:----|
|CloudChecker|azure_ip_range|Source URL of Azure Datacenter IP Ranges. |

This parameter is source URL of Azure Datacenter IP range. This URL is changed a few per day. So, you must get the latest URL from link "click here to download manually" of page "[Microsoft Azure Datacenter IP Ranges](https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653)" and set it to above parameter before execute GyoiThon.  

#### 3. Machine Learning analysis mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -m
```

By add `-m` option, GyoiThon identifies products/version using Machine Learning (Naive Bayes) in addition to default mode.  

#### 4. Google Hacking mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -g
```

By add `-g` option, GyoiThon identifies products/version using Google Custom Search API in addition to default mode. Before execution, you must set [API key](https://console.cloud.google.com/apis/dashboard) and [Search engine ID](https://support.google.com/customsearch/answer/2649143?hl=ja) to the below parameters.  

|Category|Parameter|Description|
|:----|:----|:----|
|GoogleHack|api_key|API key of Google Custom Search API. |
||search_engine_id|Google search engine ID. |

| Note |
|:-----|
| You can use free Google Custom Search API of 100 queries per day. But, if you want to use more than 100 queries, you must pay fee the Google Custom Search API service. |

#### 5. Exploration of default contents mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -e
```

By add -e option, GyoiThon explores the default contents of products such as CMS, Web server software in addition to default mode.  
By change the parameters in `config.ini`, you can change setting of exploration.  

|Category|Parameter|Description|
|:----|:----|:----|
|ContentExplorer|delay_time|Delay time of exploration. Default value is `1` (sec). |

| Note |
|:-----|
| When you use this option, may be affected to heavy load of server because of GyoiThon execute numerous accesses (hundreds accesses) against the target web server. In addition, by numerous 404 error logs are wrote to access log, it may be to caught by SOC (Security Operation Center). So, if you use this option, **please notify person concerned such as SOC, administrator and use them in an environment under your control and at your own risk and**. |

#### 6. Censys cooperation mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -c
```

By add `-c` option, GyoiThon examines open port number and server certification using [Censys](https://censys.io/).  
Before execution, you must set API key and Secret key to the below parameters.  

|Category|Parameter|Description|
|:----|:----|:----|
|Censys|api_id|API key of Censys. |
||secret|Secret key of Censys. |

#### 7. Metasploit cooperation mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -p
```

By add `-p` option, GyoiThon examines real vulnerabilities such as DoS and backdoor using Metasploit in addition to default mode.  
Before execution, you must launch RPC server of Metasploit and set below parameters in `config.ini`.  

|Category|Parameter|Description|
|:----|:----|:----|
|Exploit|server_host|Allocated IP address to the RPC Server (`msgrpc`). |
||server_port|Allocated port number to the RPC Server (`msgrpc`). |
||msgrpc_user|User ID for authorization of `msgrpc`. |
||msgrpc_pass|Password for authorization of `msgrpc`. |
||LHOST|Allocated IP address to the RPC Server (`msgrpc`).|

| Note |
|:-----|
| When you use this option, may be heavily affected to server operation because of GyoiThon execute the exploit against the target web server. In addition, this option may be caught by SOC (Security Operation Center) because of exploits are like a real attacks. So, if you use this option, **please notify person concerned such as SOC, administrator and use them in an environment under your control and at your own risk and**. |

#### 8. Stored logs based analysis mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -l "Full path of stored logs"
```

By add `-l` option, GyoiThon executes various examination using stored HTTP responses without web crawling.  

This mode assumes the web application that GyoiThon cannot execute web crawling.  
GyoiThon can execute various examination similar web crawling of default mode using stored HTTP responses gathered by local proxy tool.  

| Note |
|:-----|
| Log file's extension is `.log`. |

#### <a name='complex_mode'>9. Combination of multiple options</a>.  
##### Combination of "Examination of cloud services mode" and "Machine Learning analysis mode".
```
root@kali:~/GyoiThon# python3 gyoithon.py -s -m
```

##### Combination of "Examination of cloud services mode" and "Google Hacking mode".
```
root@kali:~/GyoiThon# python3 gyoithon.py -s -g
```

##### Combination of "Examination of cloud services mode", "Machine Learning analysis mode" and "Google Hacking mode".
```
root@kali:~/GyoiThon# python3 gyoithon.py -s -m -g
```

#### All option.
```
root@kali:~/GyoiThon# python3 gyoithon.py -s -m -g -e -c -p -l "Full path of stored logs"
```

### Check report.  
After finished execution of GyoiThon, reports of each target are generated to the following path.    

```
root@kali:~/GyoiThon/report# ls
gyoithon_report_192.168.220.129_1082018338.csv
gyoithon_report_192.168.220.129_bodgeit.csv
gyoithon_report_192.168.220.129_cyclone.csv
gyoithon_report_192.168.220.129_vicnum.csv
gyoithon_report_192.168.220.129_WackoPicko.csv
```

Report format is `gyoithon_report_target FQDN(or IP address)_Root Path.csv`.  
Each column's detail is following.  

|Column|Description|Example|
|:----|:----|:----|
|fqdn|FQDN of target web server.|`www.gyoithon.example.com`|
|ip_addr|IP address of target web server.|`192.168.220.129`|
|port|Port number of target web server.|80|
|cloud_type|Cloud service name (Azure or AWS or GCP or Unknown).|`AWS`|
|method|Examination way of GyoiThon.|`Crawling`|
|url|Accessed URL.|`http://192.168.220.129:80/WackoPicko/admin/index.php?page=login`|
|vendor_name|Vendor name of identified products.|`apache`|
|prod_name|Identified products.|`http_server`|
|prod_version|Version of identified products.|`2.2.14`|
|prod_trigger|Trigger of identified products.|`Apache/2.2.14`|
|prod_type|Product category (Web or CMS or Framework etc..).|`Web`|
|prod_vuln|CVE number according to identified products (desc CVSS score).|`CVE-2017-3167, CVE-2017-3169, CVE-2017-7668` ...|
|origin_login|Login page is existing or not (Log: Analysis using Machine Leaerning, Url: Analysis using string pattern matching in URL.|`Log : 37.5 %\nUrl : 100.0 %`|
|origin_login_trigger|Trigger of identifed login page.|`Log : name",<input type="password"\nUrl : login`|
|wrong_comment|Identified unnecessary comments.|`パスワードは「password1234」です。`|
|error_msg|Identified unnecessary debug messages.|`Warning: mysql_connect() ..snip.. in auth.php on line 38`|
|server_header|Server header of HTTP response.|`Server: Apache/2.2.14 (Ubuntu) mod_mono/2.4.3 PHP/5.3.2`|
|log|Path of raw data.|`/usr/home/~snip~/http_192.168.220.129_80_20181112170525765.log`|
|date|Examination date.|`2018/11/12  17:05:25`|

## <a name='Tips'>Tips</a>
### 1. How to add new signature (string matching patterns).  
`signatures` path includes below files.  

```
root@kali:~/GyoiThon/signatures/ ls
signature_product.txt
signature_default_content.txt
signature_search_query.txt
signature_comment.txt
signature_error.txt
signature_page_type_from_url.txt
```

#### `signature_product.txt`  
This is string matching patterns for identification of product in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   
 
```
Format: field1@field2@field3@field4@field5
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Required|1|Product Category.|`CMS`|
|Required|2|Vendor name.|`drupal`|
|Required|3|Product name.|`drupal`|
|Optional|4|Version binded with this signature.|`8.0` |
|Required|5|Regex of identifying product.|`.*(X-Generator: Drupal 8).*`|

If you don't need optional field, you must set `*` to this field.  
 
* Example  
```
CMS@wordpress@wordpress@*@.*(WordPress ([0-9]+[\.0-9]*[\.0-9]*)).*
CMS@drupal@drupal@8.0@.*(X-Generator: Drupal 8).*
```

| Note |
|:-----|
| If you want to extract product version, you write two regex groups (**the second regex is used for version extraction**). |

#### `signature_default_content.txt`  
This is string matching patterns for identification of product in <a name='explore_contents_mode'>Exploration of default contents mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1@field2@field3@field4@field5@field6@field7@field8
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Required|1|Product Category.|`CMS`|
|Required|2|Vendor name.|`sixapart`|
|Required|3|Product name.|`movabletype`|
|Optional|4|Version binded with this signature.|`*` |
|Required|5|Explore path|`/readme.html`|
|Optional|6|Regex of to confirm product.|`.*(Movable Type).*`|
|Optional|7|Regex of identifying version.|`(v=([0-9]+[\.0-9]*[\.0-9]*))`|
|Required|8|Login page or not.|Login page is `1`, Not login page is `0`|

If you don't need optional field, you must set `*` to this field.  

* Example  
```
Web@apache@http_server@*@/server-status@*@Version:.*(Apache/([0-9]+[\.0-9]*[\.0-9]*))@0
CMS@sixapart@movabletype@*@/readme.html@.*(Movable Type).*@(v=([0-9]+[\.0-9]*[\.0-9]*))@0
```

| Note |
|:-----|
| If you want to extract product version, you write two regex groups (**the second regex is used for version extraction**). |

| Note |
|:-----|
| If GyoiThon cannot confirm the product by just `Explore path`, you need to indicate the `Regex of to confirm product` field. GyoiThon accesses the URL that `Explore path` and examines the HTTP response using `Regex of to confirm product`. If this regex matches, GyoiThon judges that the product exists. |

#### `signature_search_query.txt`  
This is Google Custom Search query for identification of product in <a name='google_hacking_mode'>Google Hacking mode</a>.  
If you want to add new query, you have to write it such following format.   

```
Format: field1@field2@field3@field4@field5@field6@field7@field8
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Optional|1|Product Category.|`CMS`|
|Optional|2|Vendor name.|`sixapart`|
|Optional|3|Product name.|`movabletype`|
|Optional|4|Version binded with this signature.|`*` |
|Required|5|Google Custom Search query|`inurl:/readme.html`|
|Optional|6|Regex of to confirm product.|`.*(Movable Type).*`|
|Optional|7|Regex of identifying version.|`(v=([0-9]+[\.0-9]*[\.0-9]*))`|
|Optional|8|Login page or not.|Login page is `1`, Not login page is `0`|

If you don't need optional field, you must set `*` to this field.  

* Example  
```
Web@apache@http_server@*@inurl:/server-status@*@Version:.*(Apache/([0-9]+[\.0-9]*[\.0-9]*))@0
CMS@sixapart@movabletype@*@inurl:/readme.html@.*(Movable Type).*@(v=([0-9]+[\.0-9]*[\.0-9]*))@0
*@*@*@*@filetype:bak@*@*@0
```

| Note |
|:-----|
| If you want to extract product version, you write two regex groups (**the second regex is used for version extraction**). |

| Note |
|:-----|
| If GyoiThon cannot confirm the product by just `Google Custom Search query`, you need to indicate the `Regex of to confirm product` field. GyoiThon accesses the URL included in the execution result of Google Custom Search API and examines the HTTP response using `Regex of to confirm product`. If this regex matches, GyoiThon judges that the product exists. |

#### `signature_comment.txt`  
This is string matching patterns for identification of unnecessary comments in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Regex of unnecessary comment.|

* Example  
```
(user\s*=|[\"']user[\"']\s*:|user_id\s*=|[\"']user_id[\"']\s*:|id\s*=|[\"']id[\"']\s*:)
(select\s+[\s\r\n\w\d,\"']*\s+from)
```

#### `signature_error.txt`  
This is string matching patterns for identification of unnecessary debug message in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Regex of unnecessary debug message.|

* Example  
```
(ORA-[0-9a-zA-Z\.])
(fail|error|notice|parse|warning|fatal)[^\n]*line[^\n]*[0-9]+
```

#### `signature_page_type_from_url.txt`  
This is string matching patterns for URL based identification of page type in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1@field2
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Page type.|
|Required|2|Regex of identifying page type.|

* Example  
```
Login@.*(login|log_in|logon|log_on|signin|sign_in).*
```

|Note|
|:---|
|Above vendor name and product name must be match a name in [CPE format](https://en.wikipedia.org/wiki/Common_Platform_Enumeration).|

### 2. How to add learning data.  
`modules/train_data/` path includes two train data for Machine Learning.  

```
root@kali:~/GyoiThon/modules/train_data/ ls
train_cms_in.txt
train_page_type.txt
```

#### `train_cms_in.txt`  
This is train data for Machine Learning analysis in <a name='machine_learning_mode'>Machine Learning mode</a>.  
If you want to add new train data, you have to write it such following format.   

```
Format: field1@field2@field3@field4
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Required|1|Vendor name.|`joomla`|
|Required|2|Product name.|`joomla\!`|
|Optional|3|Version binded with this train data.|`*` |
|Required|4|Feature of product expressed by regex.|`(Set-Cookie: [a-z0-9]{32}=.*);`|

If you don't need optional field, you must set `*` to this field.  

* Example  
```
joomla@joomla\!@*@(Set-Cookie: [a-z0-9]{32}=.*);
joomla@joomla\!@*@(Set-Cookie: .*=[a-z0-9]{26,32});
heartcore@heartcore@*@(Set-Cookie:.*=[A-Z0-9]{32});.*
heartcore@heartcore@*@(<meta name=["']author["'] content=["']{2}).*
```

|Note|
|:---|
|Above vendor name and product name must be match a name in [CPE format](https://en.wikipedia.org/wiki/Common_Platform_Enumeration).|

#### `train_page_type.txt`  
This is train data for identifying page type usin Machine Learning in <a name='default_mode'>default mode</a>.  
If you want to add new train data, you have to write it such following format.   

```
Format: field1@field2
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Category.|
|Required|2|Feature of page expressed by regex.|

* Example  
```
Login@.*(<input.*type=[\"']text[\"'].*name=[\"']user|uid|username|user_name|name[\"']).*>
Login@.*(<input.*type=[\"']password[\"']).*>
```

### 3. How to change "Exploit module's option".
When GyoiThon exploits, it uses **default value** of Exploit module options.  
If you want to change option values, please input any value to `"user_specify"` in `exploit_tree.json` as following.  

```
root@kali:~/GyoiThon/modules/data/ ls
exploit_tree.json
root@kali:~/GyoiThon/modules/data/ vim exploit_tree.json

...snip...

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

## Operation check environment
 * Kali Linux 2018.2 (for Metasploit)  
   * CPU: Intel(R) Core(TM) i5-5200U 2.20GHz  
   * Memory: 8.0GB  
   * Metasploit Framework 4.16.48-dev  
   * Python 3.6.1 (Anaconda3)  
 * Dependent Python libraries  
   * censys==0.0.8  
   * docopt==0.6.2  
   * google-api-python-client==1.7.4
   * jinja2==2.10  
   * msgpack-python==0.5.6  
   * pandas==0.23.4  
   * urllib3==1.23  
   * Scrapy==1.5.1  

## Licence
[Apache License 2.0](https://github.com/gyoisamurai/GyoiThon/blob/master/LICENSE)

## Contact us
 gyoiler3@gmail.com  

 * [Masafumi Masuya](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#masafumi-masuya-36855)  
 [https://twitter.com/gyoizamurai](https://twitter.com/gyoizamurai)
 * [Toshitsugu Yoneyama](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#toshitsugu-yoneyama-36864)  
 [https://twitter.com/yoneyoneyo](https://twitter.com/yoneyoneyo)
 * [Isao Takaesu](https://www.blackhat.com/asia-18/arsenal/schedule/presenters.html#isao-takaesu-33544)  
 [https://twitter.com/bbr_bbq](https://twitter.com/bbr_bbq)
