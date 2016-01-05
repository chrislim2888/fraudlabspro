<?php
/* Copyright (C) 2013-2014 FraudLabsPro.com
 * All Rights Reserved
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Purpose: Class to implement fraud checking solution using FraudLabs Pro service.
 * 	        API Key required, and if you do not have an API key, you may sign up free
 * 			at http://www.fraudlabspro.com
 */

class FraudLabsPro {
	private $apiKey;
	public $flpRequest;
	public $flpResponse;		//Will be instantiated on success fraudCheck for returnAs=>string option only

	// Constructor
	public function __construct($apiKey=''){
		// Store the api key for calling
		if(!preg_match('/^[A-Z0-9]{32}$/', $apiKey)) throw new exception('FraudLabsPro: Invalid API key provided.');

		$this->apiKey = $apiKey;
		$this->flpRequest = new Flp_Request();
		$this->flpResponse = NULL;
	}

	// Destructor
	public function __destruct(){
		unset($flpRequest);
		unset($flpResponse);
	}

	///////////////////////////////////////
	// Purpose: perform fraud check
	// Input:
	//	returnAs:	json - return json result
	//				xml - return xml result
	//				string - return fraud status in string (APPROVE, REVIEW, REJECT, <ERROR MESSAGE>)
	//
	// Output:
	//	Depend on the returnAs param
	///////////////////////////////////////
	public function fraudCheck($returnAs = 'string'){
		//reset the variable prior to insertion
		unset($this->response);

		// Perform validation (where applicable) and construct the REST queries
		$params = 'key=' . $this->apiKey;

		if (is_null($this->flpRequest->ipAddress)){
			//Default IP Address if null
			$this->flpRequest->ipAddress = $_SERVER['REMOTE_ADDR'];
		}
		$params .= '&ip=' . $this->flpRequest->ipAddress;

		switch ($returnAs){
			case 'string':
				$params .= '&format=json';
				break;

			case 'json':
				$params .= '&format=json';
				break;

			case 'xml':
				$params .= '&format=xml';
				break;

			default:
				$params .= '&format=json';
		}

		if (!is_null($this->flpRequest->firstName)){
			$params .= '&first_name=' . rawurlencode($this->flpRequest->firstName);
		}
		
		if (!is_null($this->flpRequest->lastName)){
			$params .= '&bill_city=' . rawurlencode($this->flpRequest->lastName);
		}


		if (!is_null($this->flpRequest->billingCity)){
			$params .= '&bill_city=' . rawurlencode($this->flpRequest->billingCity);
		}

		if (!is_null($this->flpRequest->billingZIPCode)){
			$params .= '&bill_zip_code=' . rawurlencode($this->flpRequest->billingZIPCode);
		}

		if (!is_null($this->flpRequest->billingState)){
			$params .= '&bill_state=' . rawurlencode($this->flpRequest->billingState);
		}

		if (!is_null($this->flpRequest->billingCountry)){
			if(!$this->isCountryCode($this->flpRequest->billingCountry)) throw new exception('FraudLabsPro->fraudCheck(): [billingCountry] Invalid country code.');

			$params .= '&bill_country=' . rawurlencode($this->flpRequest->billingCountry);
		}

		if (!is_null($this->flpRequest->shippingAddress)){
			$params .= '&ship_addr=' . rawurlencode($this->flpRequest->shippingAddress);
		}

		if (!is_null($this->flpRequest->shippingCity)){
			$params .= '&ship_city=' . rawurlencode($this->flpRequest->shippingCity);
		}

		if (!is_null($this->flpRequest->shippingZIPCode)){
			$params .= '&ship_zip_code=' . rawurlencode($this->flpRequest->shippingZIPCode);
		}

		if (!is_null($this->flpRequest->shippingState)){
			$params .= '&ship_state=' . rawurlencode(urlencode($this->flpRequest->shippingState));
		}

		if (!is_null($this->flpRequest->shippingCountry)){
			if(!$this->isCountryCode($this->flpRequest->shippingCountry)) throw new exception('FraudLabsPro->fraudCheck(): [shippingCountry] Invalid country code.');

			$params .= '&ship_country=' . rawurlencode($this->flpRequest->shippingCountry);
		}

		if (!is_null($this->flpRequest->emailAddress)){
			//Validate email address
			if(!filter_var($this->flpRequest->emailAddress, FILTER_VALIDATE_EMAIL)) throw new exception('FraudLabsPro->fraudCheck(): [emailAddress] Invalid email address provided.');

			//Prepare the email adomain and hash for checking
			$params .= '&email_domain=' . rawurlencode(substr($this->flpRequest->emailAddress, strpos($this->flpRequest->emailAddress, '@')+1));
			$params .= '&email=' . rawurlencode($this->flpRequest->emailAddress);
			$params .= '&email_hash=' . rawurlencode($this->doHash($this->flpRequest->emailAddress));
		}

		if (!is_null($this->flpRequest->username)){
			$params .= '&username_hash=' . rawurlencode($this->doHash($this->flpRequest->username));
		}

		if (!is_null($this->flpRequest->password)){
			$params .= '&password_hash=' . rawurlencode($this->doHash($this->flpRequest->password));
		}

		if (!is_null($this->flpRequest->creditCardNumber)){
			$params .= '&bin_no=' . rawurlencode(substr(preg_replace('/\D/', '', $this->flpRequest->creditCardNumber), 0, 6));
			$params .= '&card_hash=' . rawurlencode($this->doHash(preg_replace('/\D/', '', $this->flpRequest->creditCardNumber)));
		}

		if (!is_null($this->flpRequest->phone)){
			$params .= '&user_phone=' . rawurlencode(preg_replace('/\D/', '', $this->flpRequest->phone));
		}

		if (!is_null($this->flpRequest->bankName)){
			$params .= '&bin_bank_name=' . rawurlencode($this->flpRequest->bankName);
		}

		if (!is_null($this->flpRequest->bankPhone)){
			$params .= '&bin_bank_phone=' . rawurlencode(preg_replace('/\D/', '', $this->flpRequest->bankPhone));
		}

		if (!is_null($this->flpRequest->avsResult)){
			$params .= '&avs_result=' . rawurlencode($this->flpRequest->avsResult);
		}

		if (!is_null($this->flpRequest->cvvResult)){
			$params .= '&cvv_result=' . rawurlencode($this->flpRequest->cvvResult);
		}

		if (!is_null($this->flpRequest->orderId)){
			$params .= '&user_order_id=' . rawurlencode($this->flpRequest->orderId);
		}

		if (!is_null($this->flpRequest->amount)){
			$params .= '&amount=' . rawurlencode($this->flpRequest->amount);
		}

		if (!is_null($this->flpRequest->quantity)){
			$params .= '&quantity=' . rawurlencode($this->flpRequest->quantity);
		}

		if (!is_null($this->flpRequest->currency)){
			$params .= '&currency=' . rawurlencode($this->flpRequest->currency);
		}

		if (!is_null($this->flpRequest->department)){
			$params .= '&department=' . rawurlencode(urlencode($this->flpRequest->department));
		}

		if (!is_null($this->flpRequest->paymentMode)){
			if(!$this->isValidPaymentMode($this->flpRequest->paymentMode)) throw new exception('FraudLabsPro->fraudCheck(): [paymentMode] Invalid payment mode. Valid values are creditcard, paypal, googlecheckout, cod, moneyorder, wired, bankdeposit, others');

			$params .= '&payment_mode=' . rawurlencode($this->flpRequest->paymentMode);
		}

		if (!is_null($this->flpRequest->sessionId)){
			$params .= '&session_id=' . rawurlencode($this->flpRequest->sessionId);
		}
		
		if (!is_null($this->flpRequest->flpChecksum)){
			$params .= '&flp_checksum=' . rawurlencode($this->flpRequest->flpChecksum);
		}

		//Perform fraud check (3 tries on fails)
		$retry = 0;
		while($retry++ < 3){
			$result = $this->http('https://api.fraudlabspro.com/v1/order/screen?' . $params);
			if($result) break;
			sleep(2);
		}

		//Return value to caller
		switch($returnAs){
			case 'string':
				if(!is_null($json = json_decode($result))){
					//create response object
					$this->flpResponse = new Flp_Response();
					$this->flpResponse->decodeJsonResult($result);

					if (intval($json->fraudlabspro_error_code) == 0)
						return $json->fraudlabspro_status;
					else
						return $json->fraudlabspro_message;
				}
				else
					return '';

			//return json or xml depends on user defined
			default:
				return $result;
		}
	}
	
	///////////////////////////////////////
	// Purpose: feedback the order status
	// Input:
	//	transactionID - transaction ID
	//	action - APPROVE, REJECT
	//	returnAs:	json - return json result
	//				xml - return xml result
	//
	// Output:
	//	Depend on the returnAs param
	///////////////////////////////////////
	public function feedbackOrder($transactionID, $action, $returnAs = 'json'){
		// Perform validation (where applicable) and construct the REST queries
		$params = 'key=' . $this->apiKey;
		$params .= '&id=' . rawurlencode($transactionID);
		
		if (in_array($action, array('APPROVE', 'REJECT'))){
			$params .= '&action=' . $action;
		}
		else
			return NULL;
			
		if (in_array($returnAs, array('json', 'xml'))){
			$params .= '&format=' . $returnAs;
		}
		else
			return NULL;
			
		//Perform fraud check (3 tries on fails)
		$retry = 0;
		while($retry++ < 3){
			$result = $this->http('https://api.fraudlabspro.com/v1/order/feedback?' . $params);
			if($result) break;
			sleep(2);
		}

		//Return value to caller
		return $result;
	}
	
	// List of ISO-3166 country codes for validation before sent
	private function isCountryCode($cc){
		if(!$cc) return false;

		return in_array($cc, array('AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CS', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI', 'VN', 'VU', 'WF', 'WS', 'XK', 'YE', 'YT', 'ZA', 'ZM', 'ZW'));
	}

	// List of support payment mode
	private function isValidPaymentMode($payment_mode){
		if(!$payment_mode) return false;

		return in_array($payment_mode, array('creditcard', 'paypal', 'googlecheckout', 'cod', 'moneyorder', 'wired', 'bankdeposit', 'others'));
	}

	// Do the hashing. This applies to several params, i.e, email, username, password and credit card number
	private function doHash($s, $prefix='fraudlabspro_'){
		$hash = $prefix . $s;
		for($i=0; $i<65536; $i++) $hash = sha1($prefix . $hash);

		return $hash;
	}

	// Perform the HTTP query
	private function http($url){
		if(!function_exists('curl_init')) throw new exception('FraudLabsPro: cURL extension is not enabled.');

		$ch = curl_init();
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_URL, $url);
		//curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_TIMEOUT, 60);
		curl_setopt($ch, CURLOPT_USERAGENT, 'FraudLabsPro API Client 1.0.0');

		$response = curl_exec($ch);

		if(empty($response) || curl_error($ch) || curl_getinfo($ch, CURLINFO_HTTP_CODE) !== 200){
			curl_close($ch);
			return false;
		}

		curl_close($ch);

		return $response;
	}
}

class Flp_Request{
	public $ipAddress = NULL;
	public $billingCity = NULL;
	public $billingZIPCode = NULL;
	public $billingState = NULL;
	public $billingCountry = NULL;
	public $shippingAddress = NULL;
	public $shippingCity = NULL;
	public $shippingZIPCode = NULL;
	public $shippingState = NULL;
	public $shippingCountry = NULL;
	public $emailAddress = NULL;
	public $username = NULL;
	public $password = NULL;
	public $creditCardNumber = NULL;
	public $phone = NULL;
	public $bankName = NULL;
	public $bankPhone = NULL;
	public $avsResult = NULL;
	public $cvvResult = NULL;
	public $orderId = NULL;
	public $amount = NULL;
	public $quantity = NULL;
	public $currency = NULL;
	public $department = NULL;
	public $paymentMode = NULL;
	public $sessionId = NULL;
	public $lastName = NULL;
	public $firstName = NULL;
	public $flpChecksum = NULL;
	

	//Reset the variables
	public function reset(){
		$this->ipAddress = NULL;
		$this->billingCity = NULL;
		$this->billingZIPCode = NULL;
		$this->billingState = NULL;
		$this->billingCountry = NULL;
		$this->shippingAddress = NULL;
		$this->shippingCity = NULL;
		$this->shippingZIPCode = NULL;
		$this->shippingState = NULL;
		$this->shippingCountry = NULL;
		$this->emailAddress = NULL;
		$this->username = NULL;
		$this->password = NULL;
		$this->creditCardNumber = NULL;
		$this->phone = NULL;
		$this->bankName = NULL;
		$this->bankPhone = NULL;
		$this->avsResult = NULL;
		$this->cvvResult = NULL;
		$this->orderId = NULL;
		$this->amount = NULL;
		$this->quantity = NULL;
		$this->currency = NULL;
		$this->department = NULL;
		$this->paymentMode = NULL;
		$this->sessionId = NULL;
		$this->lastName = NULL;
		$this->firstName = NULL;
		$this->flpChecksum = NULL;
	}
}

class Flp_Response{
	public $isCountryMatch = '';
	public $isHighRiskCountry = '';
	public $distanceInKm = 0;
	public $distanceInMile = 0;
	public $ipCountry = '';
	public $ipRegion = '';
	public $ipCity = '';
	public $ipContinent = '';
	public $ipLatitude = '';
	public $ipLongitude = '';
	public $ipTimezone = '';
	public $ipElevation = '';
	public $ipDomain = '';
	public $ipMobileMnc = '';
	public $ipMobileMcc = '';
	public $ipMobileBrand = '';
	public $ipNetspeed = '';
	public $ipIspName = '';
	public $ipUsageType = '';
	public $isFreeEmail = '';
	public $isNewDomainName = '';
	public $isProxyIpAddress = '';
	public $isBinFound = '';
	public $isBinCountryMatch = '';
	public $isBinNameMatch = '';
	public $isBinPrepaid = '';
	public $isAddressShipForward = '';
	public $isBillShipCityMatch = '';
	public $isBillShipStateMatch = '';
	public $isBillShipCountryMatch = '';
	public $isBillShipPostalMatch = '';
	public $isIpBlacklist = '';
	public $isEmailBlacklist = '';
	public $isCreditCardBlacklist = '';
	public $isDeviceBlacklist = '';
	public $userOrderId = '';
	public $userOrderMemo = '';
	public $fraudlabsproScore = '';
	public $fraudlabsproDistribution = '';
	public $fraudlabsproStatus = '';
	public $fraudlabsproId = '';
	public $fraudlabsproVersion = '';
	public $fraudlabsproErrorCode = '';
	public $fraudlabsproMessage = '';
	public $fraudlabsproCredits = '';

	//Reset the variables
	public function reset(){
		$this->isCountryMatch = '';
		$this->isHighRiskCountry = '';
		$this->distanceInKm = 0;
		$this->distanceInMile = 0;
		$this->ipCountry = '';
		$this->ipRegion = '';
		$this->ipCity = '';
		$this->ipContinent = '';
		$this->ipLatitude = '';
		$this->ipLongitude = '';
		$this->ipTimezone = '';
		$this->ipElevation = '';
		$this->ipDomain = '';
		$this->ipMobileMnc = '';
		$this->ipMobileMcc = '';
		$this->ipMobileBrand = '';
		$this->ipNetspeed = '';
		$this->ipIspName = '';
		$this->ipUsageType = '';
		$this->isFreeEmail = '';
		$this->isNewDomainName = '';
		$this->isProxyIpAddress = '';
		$this->isBinFound = '';
		$this->isBinCountryMatch = '';
		$this->isBinNameMatch = '';
		$this->isBinPrepaid = '';
		$this->isAddressShipForward = '';
		$this->isBillShipCityMatch = '';
		$this->isBillShipStateMatch = '';
		$this->isBillShipCountryMatch = '';
		$this->isBillShipPostalMatch = '';
		$this->isIpBlacklist = '';
		$this->isEmailBlacklist = '';
		$this->isCreditCardBlacklist = '';
		$this->isDeviceBlacklist = '';
		$this->userOrderId = '';
		$this->userOrderMemo = '';
		$this->fraudlabsproScore = '';
		$this->fraudlabsproDistribution = '';
		$this->fraudlabsproStatus = '';
		$this->fraudlabsproId = '';
		$this->fraudlabsproVersion = '';
		$this->fraudlabsproErrorCode = '';
		$this->fraudlabsproMessage = '';
		$this->fraudlabsproCredits = '';
	}

	//Decode the json result returns from FraudLabs Pro screen order
	public function decodeJsonResult($result){
		if(!is_null($json = json_decode($result))){
			$this->isCountryMatch = $json->is_country_match;
			$this->isHighRiskCountry = $json->is_high_risk_country;
			$this->distanceInKm = $json->distance_in_km;
			$this->distanceInMile = $json->distance_in_mile;
			$this->ipCountry = $json->ip_country;
			$this->ipRegion = $json->ip_region;
			$this->ipCity = $json->ip_city;
			$this->ipContinent = $json->ip_continent;
			$this->ipLatitude = $json->ip_latitude;
			$this->ipLongitude = $json->ip_longitude;
			$this->ipTimezone = $json->ip_timezone;
			$this->ipElevation = $json->ip_elevation;
			$this->ipDomain = $json->ip_domain;
			$this->ipMobileMnc = $json->ip_mobile_mnc;
			$this->ipMobileMcc = $json->ip_mobile_mcc;
			$this->ipMobileBrand = $json->ip_mobile_brand;
			$this->ipNetspeed = $json->ip_netspeed;
			$this->ipIspName = $json->ip_isp_name;
			$this->ipUsageType = $json->ip_usage_type;
			$this->isFreeEmail = $json->is_free_email;
			$this->isNewDomainName = $json->is_new_domain_name;
			$this->isProxyIpAddress = $json->is_proxy_ip_address;
			$this->isBinFound = $json->is_bin_found;
			$this->isBinCountryMatch = $json->is_bin_country_match;
			$this->isBinNameMatch = $json->is_bin_name_match;
			$this->isBinPrepaid = $json->is_bin_prepaid;
			$this->isAddressShipForward = $json->is_address_ship_forward;
			$this->isBillShipCityMatch = $json->is_bill_ship_city_match;
			$this->isBillShipStateMatch = $json->is_bill_ship_state_match;
			$this->isBillShipCountryMatch = $json->is_bill_ship_country_match;
			$this->isBillShipPostalMatch = $json->is_bill_ship_postal_match;
			$this->isIpBlacklist = $json->is_ip_blacklist;
			$this->isEmailBlacklist = $json->is_email_blacklist;
			$this->isCreditCardBlacklist = $json->is_credit_card_blacklist;
			$this->isDeviceBlacklist = $json->is_device_blacklist;
			$this->userOrderId = $json->user_order_id;
			$this->userOrderMemo = $json->user_order_memo;
			$this->fraudlabsproScore = $json->fraudlabspro_score;
			$this->fraudlabsproDistribution = $json->fraudlabspro_distribution;
			$this->fraudlabsproStatus = $json->fraudlabspro_status;
			$this->fraudlabsproId = $json->fraudlabspro_id;
			$this->fraudlabsproVersion = $json->fraudlabspro_version;
			$this->fraudlabsproErrorCode = $json->fraudlabspro_error_code;
			$this->fraudlabsproMessage = $json->fraudlabspro_message;
			$this->fraudlabsproCredits = $json->fraudlabspro_credits;
		}
	}
}
?>
