<?php
	/*******************************
	 * Example to do a fraud check for a credit card sales order
	 * 
	 *******************************/
	 
	require('FraudLabsPro.class.php');
	
	///////////////////////////////
	// Create FraudLabs Pro object
	// Note: You need to enter the API key during the instantiation
	//       If you do not have the api key, register it free at http://www.fraudlabspro.com
	$flp = new FraudLabsPro('<API_KEY>');
	
	/////////////////////////////////////////////////
	// Enter sales order information for fraud check
	// For example:
	//    Ship item to US, bill to MY, pay with credit card
	//	  Amount: $123.00 for 1 item
	$flp->flpRequest->billingCity = 'Bayan Lepas';
	$flp->flpRequest->billingZIPCode = '11950';
	$flp->flpRequest->billingState = 'Bayan Lepas';
	$flp->flpRequest->billingCountry = 'MY';
	$flp->flpRequest->shippingAddress = '12, street address';
	$flp->flpRequest->shippingCity = 'NY';
	$flp->flpRequest->shippingZIPCode = '00001';
	$flp->flpRequest->shippingState = 'NY';
	$flp->flpRequest->shippingCountry = 'US';
	$flp->flpRequest->emailAddress = 'hello@example.com';
	$flp->flpRequest->creditCardNumber = '1111111111111111';
	$flp->flpRequest->bankName = 'BANKNAME';
	$flp->flpRequest->orderId = 'order123';
	$flp->flpRequest->amount = 123.00;
	$flp->flpRequest->quantity = 1;
	$flp->flpRequest->currency = 'USD';
	$flp->flpRequest->paymentMode = 'creditcard';
	
	// Invoke fraud check
	$result = $flp->fraudCheck('string');
	
	////////////////////////////
	// Get the result
	// Note: Fraud Score provide you the indicator of the possible fraud.
	//		 Fraud Status provide you the action if the order is APPROVE, REJECT or REVIEW,
	//		 in conjuction with the use of FraudLabsPro custom rules
	echo "Fraud Score: " . $flp->flpResponse->fraudlabsproScore . "<br/>";
	echo "Fraud Status: " . $flp->flpResponse->fraudlabsproStatus . "<br/>";
	
	if ($flp->flpResponse->fraudlabsproStatus == "APPROVE"){
		//TODO: logic for approved order
	}
	else if ($flp->flpResponse->fraudlabsproStatus == "REVIEW"){
		//TODO: logic for review order
	}
	else if ($flp->flpResponse->fraudlabsproStatus == "REJECT"){
		//TODO: logic for rejected order
	}
	
	//clear the object
	unset($flp);
?>
