<?php
/**
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

https://eprint.iacr.org/2017/168.pdf

https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html
*/

class AES_GCM_SIV
	{	
	public $nonce,$AESblock,$p,$R,$mask0,$mask1,$mulX_GHASH,$authkey,$enckey,$blength,$A,$hbin,$h2bin; 

	function __construct($p="",$R="",$mask0="",$maks1="",$Y="",$hbin="",$h2bin="")
		{
		$this->p 	= str_repeat("0",128);
		//$this->R 	= 225=hexdec("e1");
		$this->mask0 	= str_repeat(sprintf("%08b",1),16);
		$this->mask1 	= str_repeat("01111111",16);
		$this->Y	= str_repeat("\0",16);	
		$this->hbin	= $this->h2bin = array();
		for ($k=0;$k<16;$k++) 
			{
			$this->hbin[$k]=sprintf("%04b",$k);
			$this->h2bin[$this->hbin[$k]]=dechex($k);
			}			
		}
  	
	function init($key,$nonce,$A="")
		{
		if (strlen($key)!=32 and strlen($key)!=64)
			die("Key length should be 128 or 256 bits");

		$this->nonce     = $nonce;		
		$this->AESblock	 = 'AES-'.(strlen($key)*4).'-ECB';	
		
		list ($this->authkey,$this->enckey) = $this->derive_keys($key,$nonce);
		
		// Compute mulX_GHASH
											
		$binX = str_replace($this->h2bin,$this->hbin,bin2hex($this->authkey));
		
		$xLSB = $binX[7];				
		$binX = "0".substr($binX,0,-1)&$this->mask1|substr($binX&$this->mask0,15);				
		if ($xLSB)
			$binX = substr($binX,0,-8).decbin(bindec(substr($binX,-8)) ^ 225);
		$H = $this->p^$binX;

		$result="";foreach (str_split(bin2hex($H),2) as $z) $result.=$z[1];
		
		// save cpu time: lasts 0's are irrelevant to compute mulX_GHASH
				
		$this->mulX_GHASH = rtrim(implode(array_reverse(str_split($result,8))),"0");		
		
		/*******************************************************************************/
						
		if (ctype_xdigit($A))	$A = pack("H*",$A);
		list ($this->blength,$this->A) = $this->siv_pad($A);		
		}
				    			
	function AES_GCM_SIV_encrypt($P)
	    	{
		$enckey 	= $this->enckey;if (ctype_xdigit($P)) $P = pack("H*",$P);				
		$blocks 	= str_split($P,16);
		$n		= sizeof($blocks);				
		list($bl ,$P) 	= $this->siv_pad($P);					
		$input  	= $this->A.$P.$this->blength.$bl;							
  		$Y      	= $this->siv_xor_nonce($this->siv_polyval($input));						
		$tag    	= $this->siv_tag($Y,$enckey);							
		$cblock 	= $this->siv_init_counter($tag); 	
		
		$cipher  	= openssl_encrypt($cblock, $this->AESblock, $enckey, 1)^$blocks[0];	
		
	        for ($i = 1; $i < $n; $i++) 
		    {
		    $cblock=$this->siv_inc($cblock);
		    $cipher.=openssl_encrypt($cblock, $this->AESblock, $enckey, 1)^$blocks[$i];		    
		    }
		
	        return bin2hex($cipher).$tag;
	    	} 		    

	function AES_GCM_SIV_decrypt($C)
	    	{  
		$enckey 	= $this->enckey;if (ctype_xdigit($C)) $C = pack("H*",$C);		
		$tag 	  	= bin2hex(substr($C,-16));						
		$blocks   	= str_split(substr($C,0,-16),16);						
		$cblock 	= $this->siv_init_counter($tag);										
		$n		= sizeof($blocks);
				
		$plaintext 	= openssl_encrypt($cblock, $this->AESblock, $enckey, 1)^$blocks[0];
				
	        for ($i = 1; $i < $n; $i++) 
		    {
		    $cblock=$this->siv_inc($cblock);	    
		    $plaintext.=openssl_encrypt($cblock, $this->AESblock, $enckey, 1)^$blocks[$i];	 
		    }
		 
		// now checking auth
				
		list ($bl,$C)   = $this->siv_pad($plaintext);					
		$input 		= $this->A.$C.$this->blength.$bl;
		$Y   		= $this->siv_xor_nonce($this->siv_polyval($input));						
		$expected_tag 	= $this->siv_tag($Y,$enckey);
		
		if ($expected_tag!=$tag)die("Tag authentication failed");
		  		
		return bin2hex($plaintext);
	    	}
		    
	function derive_keys($key, $nonce) 
		{
		  $len = strlen($key);$nonce=pack("H*",$nonce);		  
		  $keys="";for ($k=0;$k<(($len+1)*3)/32;$k++) $keys.=pack("H*","0$k"."000000").$nonce;		  				  
		  $kenc=openssl_encrypt($keys, $this->AESblock, pack("H*",$key), 1);
			  		  
		  $authkey 	= substr($kenc,0,8).substr($kenc,16,8);
		  $enckey 	= substr($kenc,32,8).substr($kenc,48,8);	
						
		  if ($len == 64) 			  	    			  
		        $enckey.= substr($kenc,64,8).substr($kenc,80,8);
		  	  			  
		  return [$authkey, $enckey];
		}

	function siv_pad($m)
		{
		// max plaintext length 2**32 bits = 512 MBytes
		
		$s=strlen($m);			
		$blength=pack('L',$s*8)."\0\0\0\0";
	
		$mod=$s%16;						
		if ($mod) $m.=str_repeat("\x0",16-$mod);							
			
		return [bin2hex($blength),bin2hex($m)];		
		}
		
	function siv_tag($Y,$enckey)
		{
		return substr(bin2hex(openssl_encrypt($Y, $this->AESblock, $enckey, 1)),0,32);		
		}
		
	function siv_xor_nonce($Y)
		{				
		$Y=substr_replace($Y,substr($Y,0,12)^pack("H*",$this->nonce),0,12);		
		$Y[15]=pack("i",ord($Y[15]) & 0x7f);
		return $Y; 		
		}
		
	function siv_init_counter($tag)
		{
		return strrev(strrev(pack("H*",$tag))|"\x80");			
		}
		
	function siv_inc($counter)
		{
	        for ($j = 16; $j >= 4; $j-=4) 
			{
		        $temp = substr($counter, -$j, 4);
	                extract(unpack('Lcount', $temp));		
			$counter = substr_replace($counter, pack('L', $count+1), -$j, 4);			
			if ($temp!=0xFFFFFFFF and $temp!=0xFFFFFF7F) return $counter;				
		        }
		return $counter;				
		}
		
	function siv_polyval($X)
		{
		// Work in binary-string form
							
		$GHASH	= $p2 = $this->p;
		$hbin	= $this->hbin;
		$h2bin	= $this->h2bin;				
		$X      = str_split(str_replace($h2bin,$hbin,$X), 128);	
		$binY 	= $this->mulX_GHASH;	
		
		// last binY bit is always 1, so strlen($binY)-1
						
		$lbinY  = strlen($binY)-1;
		
		// masks to fast shifting, oring and anding
		
		$mask0  = $this->mask0;
		$mask1  = $this->mask1;
																	
	        $i = 0;												
	        do 	
			{
			$GHASH^=$X[$i];	
			$binX  = "";foreach (str_split(bin2hex($GHASH),2) as $z) $binX.=$z[1];
			
			if (($GHASH=$binX)!="0")
				{
				// gf128
				
				$p = $p2;
									
				for($j=0; $j < $lbinY; $j++) 
					{							 
					if ($binY[$j]) 						
						$p^=$GHASH;			
								
					$xLSB = $GHASH[7];				
					$GHASH = "0".substr($GHASH,0,-1)&$mask1|substr($GHASH&$mask0,15);				
					if ($xLSB)
						$GHASH = substr($GHASH,0,-8).decbin(bindec(substr($GHASH,-8)) ^ 225);				 			
					}
				$GHASH^=$p;
				}
			}		
		while   (++$i<sizeof($X));

		// restore pure binary form of GHASH
						
		$temp  = "";foreach (str_split(bin2hex($GHASH),2) as $z) $temp.=$z[1];
		$GHASH = "";foreach (str_split($temp,4) as $z) $GHASH.=$h2bin[$z];
		return pack("H*",$GHASH);	
		}			 
	}

function check_AES_GCM_SIV()
	{	
	// https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html#rfc.status Appendix C. Test vectors
	
	/*
	computing time on x5690 PHP 7.3 x64
	
	https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json			 0.060553978 s
	
	more test vectors
	
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-128-gcm-siv.json	 0.029565698 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-256-gcm-siv.json	 0.029572804 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/authentication-1000.json	11.285262103 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/encryption-1000.json	11.526222744 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/random-keys-10000.json	 3.827116686 s
	*/
	
	ECHO "AES GCM SIV test vectors from https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html \n\n";
			
	$x=new AES_GCM_SIV;$n=0;
		
	if (!function_Exists("hrtime"))
		{
		function hrtime($bool) {return microtime($bool)*1000000000;}
		} 
					
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json"));

	$t=hrtime(true);
	foreach ($testvectors->AES_GCM_SIV_tests  as $test)
		{
		//echo "----------------------------------------TEST CASE ".++$n."\n\n";		
		//echo "------------------------------ivSize ".$test->ivSize." keySize ".$test->keySize." tagSize ".$test->tagSize."\n\n";		
		
		$text	= $test->msg;
		$A	= $test->aad;	
		$key	= $test->key;
		$nonce	= $test->iv;
		$tag	= $test->tag;
		$result	= $test->ct;
							
		/*echo "Plaintext 		".$text."\n";
		echo "AAD       		".$A."\n";
		echo "Key       		".$key."\n";
		echo "Nonce     		".$nonce."\n";			
		echo "Tag       		".$tag."\n";
		echo "Result    		".$result."\n\n";*/
		
		$x->init($key,$nonce,$A);							
		
		//$t1=hrtime(true);
		$D = $x->AES_GCM_SIV_decrypt($C = $x->AES_GCM_SIV_encrypt($text));
		//echo ((hrtime(true)-$t1)/1000)." microsegundos\n";
			
		/*$ctag = substr($C,-32);
		
		echo "Computed tag 	".$ctag."\n";
		echo "Computed result ".$C."\n";				
		echo "Computed dcrypt ".$D."\n\n"; */		
	
		if ($C!=$result)die("failed");					
		}
	echo ((hrtime(true)-$t)/1000000000)." s";
	}

check_AES_GCM_SIV();
