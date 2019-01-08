*  Copyright I-2019 denobisipsis

# FAST AES-GCM-SIV code with each step explained for PHP 5 & 7

# USAGE 

	$text	= "Hello World";
	$aad	= "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21";
	$key	= "f901cfe8a69615a93fdf7a98cad48179";
	$nonce	= "6245709fb18853f68d833640";
	
	$x=new AES_GCM_SIV;
	
	$x->init($key,$nonce,$aad);
	
	$cipher	= $x->AES_GCM_SIV_encrypt($text);
	
	$text 	= $x->AES_GCM_SIV_decrypt($cipher);

THERE IS A VECTOR-TEST to validate THIS AES-GCM-SIV, SIMPLY RUN check_AES_GCM_SIV()

# Support modes:

	- AES Galois Counter Mode nonce misuse-resistant (GCM-SIV)
	
# License

This code is placed in the public domain.
