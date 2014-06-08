<?php
class Alipay2 extends PaymentModule {
	protected $version = '1.4';
	protected $supportedCurrencies = array( 0 => 'CNY' );
	protected $description = 'AliPay Payment Gateway by Aveline';
	protected $lang = array(
		'english' => array(
			'Alipay2seller_email'  => 'Seller Email',
			'Alipay2security_code' => 'Security Code',
			'Alipay2partner'       => 'Partner',
			'Alipay2agent'         => 'Agent',
			'Alipay2service'       => 'Service Type',
			'Alipay2namespace'     => 'Namespace'
		),
		'chinese' => array(
			'Alipay2seller_email'  => '卖家 E-mail',
			'Alipay2security_code' => '安全校验码',
			'Alipay2partner'       => '合作者身份',
			'Alipay2agent'         => '代理商 ID',
			'Alipay2service'       => '服务类型',
			'Alipay2namespace'     => '命名空间'
		)
	);
	protected $configuration = array(
		'seller_email' => array(
			'value' => '',
			'type'  => 'input'
		),
		'security_code' => array(
			'value' => '',
			'type'  => 'input'
		),
		'partner' => array(
			'value' => '',
			'type'  => 'input'
		),
		'service' => array(
			'value' => 'create_direct_pay_by_user',
			'type'  => 'select',
			'default' => array(
				0 => 'create_direct_pay_by_user',
				1 => 'trade_create_by_buyer',
				2 => 'create_partner_trade_by_buyer'
			)
		),
		'agent' => array(
			'value' => '',
			'type'  => 'input'
		),
		'namespace' => array(
			'value' => '',
			'type'  => 'input'
		)
	);
	protected $exclude_keys = array(
		'sign',
		'sign_type',
		'cmd',
		'module',
		'ali_type_r'
	);

	protected $gateway = 'https://mapi.alipay.com/gateway.do';

	protected $form    = null;

	var $result        = array();

	function __construct() {
		parent::__construct();
		$url = Engine::singleton( )->getConfig('InstallURL');

		if (strrpos($url, '/') !== strlen($url) - 1) {
			$url .= '/';
		}
		$this->callback_url = Utilities::checkSecureUrl($url . 'includes/modules/Payment/alipay2/callback/callback.php');
		$this->return_url   = Utilities::checkSecureUrl($url . 'includes/modules/Payment/alipay2/callback/return.php');
	}

	protected function arg_sort($parameters) {
		ksort($parameters);
		reset($parameters);
		return $parameters;
	}

	protected function para_filter($parameters) {
		$filtered = array();
		while (list ($key, $val) = each ($parameters)) {
			if (in_array($key, $this->exclude_keys) || $key == "sign_type" || $val == "") {
				continue;
			} else {
				$filtered[$key] = $parameters[$key];
			}
		}
		return $filtered;
	}

	protected function md5_sign($str, $key) {
		return md5($str . $key);
	}

	protected function md5_verify($str, $key, $signature) {
		return md5($str . $key) === $signature;
	}

	protected function escape_id($str) {
		return str_replace(array( '#', ' ', '-' ), '', $str);
	}

	protected function encode_id($str) {
		return dechex(hexdec(bin2hex($this->configuration['security_code']['value'])) + hexdec(bin2hex($str)));
	}

	protected function decode_id($str) {
		return hex2bin(dechex(hexdec($str) - hexdec(bin2hex($this->configuration['security_code']['value']))));
	}

	protected function build_request_signature($parameters) {
		return $this->md5_sign($this->create_link_string($parameters), $this->configuration['security_code']['value']);
	}

	protected function build_request_parameters($parameters) {
		$parameters = $this->para_filter($parameters);
		$parameters = $this->arg_sort($parameters);

		$signature  = $this->build_request_signature($parameters);

		$parameters['sign']      = $signature;
		$parameters['sign_type'] = 'MD5';

		return $parameters;
	}

	protected function create_link_string($parameters) {
		$arg = "";
		while (list ($key, $val) = each ($parameters)) {
			$arg.=$key."=".$val."&";
		}
		$arg = substr($arg, 0, count($arg) - 2);
		if (get_magic_quotes_gpc()){
			$arg = stripslashes($arg);
		}
		return $arg;
	}

	protected function verify_signature($parameters, $signature) {
		$parameters = $this->para_filter($parameters);
		$parameters = $this->arg_sort($parameters);
		$parameters = $this->create_link_string($parameters);

		return $this->md5_verify($parameters, $this->configuration['security_code']['value'], $signature);
	}

	protected function get_verify_result($notify_id, $time_out = 60) {
		$url = $this->gateway . '?' . http_build_query(array(
			'service'   => 'notify_verify',
			'partner'   => $this->configuration['partner']['value'],
			'notify_id' => urldecode($notify_id)
		));

		$ch = curl_init($url);
		curl_setopt($ch, CURLOPT_HEADER,         0 );
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($ch, CURLOPT_TIMEOUT,        $time_out);
		curl_setopt($ch, CURLOPT_SSLVERSION,     3);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		$responseText = curl_exec($ch);
		curl_close($ch);
		return $responseText;
	}

	protected function verify_notify($data = array()) {
		if (empty($data)) {
			return false;
		}

		if (!isset($data['sign']) || !$this->verify_signature($data, $data['sign'])) {
			return false;
		}

		$responseText = 'true';
		if (isset($data['notify_id']) && !empty($data['notify_id'])) {
			$responseText = $this->get_verify_result($data['notify_id']);
		}

		return preg_match('/true$/i',$responseText);
	}

	public function drawForm($autosubmit = false) {
		$parameters = array(
			'_input_charset' => 'utf-8',
			'show_url'       => Engine::singleton()->getConfig('InstallURL'),
			'seller_email'   => $this->configuration['seller_email']['value'],
			'service'        => $this->configuration['service']['value'],
			'partner'        => $this->configuration['partner']['value'],
			'subject'        => $this->escape_id($this->invoice_id),
			'body'           => $this->escape_id($this->invoice_id),
			'notify_url'     => $this->callback_url,
			'return_url'     => $this->return_url,
			'price'          => $this->amount,
			'out_trade_no'   => $this->encode_id($this->invoice_id),
			'payment_type'   => '1',
			'quantity'       => '1',
		);

		switch($this->configuration['service']['value']) {
			case 'trade_create_by_buyer':
				$parameters['logistics_type']      = 'EXPRESS';
				$parameters['logistics_fee']       = '0.00';
				$parameters['logistics_payment']   = 'SELLER_PAY';
				break;
			case 'create_partner_trade_by_buyer':
				$parameters['logistics_type']      = 'VIRTUAL';
				$parameters['logistics_fee']       = '0.00';
				$parameters['logistics_payment']   = 'SELLER_PAY';
				$parameters['agent']               = $this->configuration['agent']['value'];
				break;
		}

		$parameters = $this->build_request_parameters($parameters);

		$form_hash   = 'form_' . uniqid();
		$action      = $this->gateway;

		$this->form .= '<form action="' . htmlspecialchars($action) . '" method="post" name="' . $form_hash . '">';
		while (list ($key, $val) = each ($parameters)) {
			$this->form .=  '<input type="hidden" name="' . htmlspecialchars($key) .'" value="' . htmlspecialchars($val) . '" />';
		}
		$this->form .= '<input type="submit" value="' . $this->paynow_text() . '" />';
		$this->form .= '</form>';

		if ($autosubmit) {
			$this->form .= '<script language="javascript">window.onload = function() { document.forms.' . $form_hash . '.submit(); }</script>';
		}

		return $this->form;
	}

	public function callback() {
		switch ($_GET['ali_type_r']) {
			case 'return':
				$r = $this->verify_notify($_GET);
				break;
			case 'callback':
				$r = $this->verify_notify($_POST);
				break;
		}


		if ($r) {
			switch ($_GET['ali_type_r']) {
			case 'return': {
					$status        = $_GET['trade_status'];
					$invoice_id    = $this->decode_id($_GET['out_trade_no']);
					$description   = (isset($_GET['subject']) ? $_GET['subject'] : '');
					$in            = $_GET['total_fee'];
					$transid       = $_GET['trade_no'];
					break;
				}

			case 'callback': {
					$status        = $_POST['trade_status'];
					$invoice_id    = $this->decode_id($_POST['out_trade_no']);
					$description   = isset($_POST['subject']) ? $_POST['subject'] : '';
					$in            = $_POST['total_fee'];
					$transid       = $_POST['trade_no'];
				}
			}


			if ($status == 'WAIT_BUYER_PAY') {
				$results = PaymentModule::PAYMENT_PENDING;
			}
			else {
				if (($status == 'TRADE_FINISHED' || $status == 'TRADE_SUCCESS')) {
					$results = PaymentModule::PAYMENT_SUCCESS;

					if (!$this->_transactionExists($transid)) {
						$this->addTransaction(array('invoice_id' => $invoice_id, 'description' => $description, 'in' => $in, 'transaction_id' => $transid, 'fee' => '0'));
					}
				}
				else {
					$results = PaymentModule::PAYMENT_FAILURE;
				}
			}

			$this->logActivity(array(
				'output' => $_POST,
				'result' => $results
			));
		}
		else {
			$this->logActivity(array(
				'output' => ($_GET['ali_type_r'] == 'callback' ? $_POST : $_GET),
				'result' => PaymentModule::PAYMENT_FAILURE
			));
		}

		if ($_GET['ali_type_r'] == 'return') {
			Utilities::redirect(Engine::singleton()->getConfig('InstallURL') . '?cmd=clientarea&action=invoice&id=' . $invoice_id);
		}
	}
}
