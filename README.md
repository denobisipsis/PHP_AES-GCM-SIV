*  Copyright I-2019 denobisipsis

# FAST AES-GCM-SIV code with each step explained for PHP 5 & 7
	Based on draft 9 https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html

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

# computing time on x5690 PHP 7.3 x64
	
	https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json			 0.060553978 s
	
	more test vectors
	
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-128-gcm-siv.json	 0.029565698 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-256-gcm-siv.json	 0.029572804 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/authentication-1000.json	11.285262103 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/encryption-1000.json	11.526222744 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/random-keys-10000.json	 3.827116686 s

	
# Support modes:

	- AES Galois Counter Mode nonce misuse-resistant (GCM-SIV)
	
# License

This code is placed in the public domain.
