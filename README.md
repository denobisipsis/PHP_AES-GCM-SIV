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
	
	https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json			 0.054485492 s
	
	more test vectors
	
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-128-gcm-siv.json	 0.026423813 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-256-gcm-siv.json	 0.026573652 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/authentication-1000.json	 9.96401935  s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/encryption-1000.json	10.043097418 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/random-keys-10000.json	 5.793678564 s

	
# Support modes:

	- AES Galois Counter Mode nonce misuse-resistant (GCM-SIV)
	
# Adenda--> dot.vs.gfmul128.php

https://github.com/denobisipsis/PHP_AES-GCM-SIV/blob/master/dot.vs.gfmul128.php

COMPUTING ON GALOIS 128-FIELDS

Functions coded:

as defined in https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf	

	- PCLMULQDQ 	
	- GFMUL     

and as defined in https://www.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.txt
	
	- mulX_POLYVAL 	
	- mulX_GHASH 	
	
	- dot_siv_ghash
	- dot_siv_polyval (in binary mode, fastest)
	
	- dot_big_math (using longs longs mode 1)
	- dot2         (using longs longs mode 2, faster)
	
# License

This code is placed in the public domain.
