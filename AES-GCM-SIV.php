<?php
/**
*  Copyright I-2019 denobisipsis

# FAST AES-GCM-SIV code with each step explained for PHP > 5.6.3

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
	public $nonce,$AESblock,$p,$R,$mask0,$mask1,$mulX_GHASH,$authkey,$enckey,$blength,$A,$hbin,$h2bin,$timeinc,$keycount,$keys,$ortag,$polytime,$sY; 

	function __construct()
		{
		// constants
		
		$this->p 	= str_repeat("0",128);
		$this->mask0 	= str_repeat(sprintf("%08b",1),16);
		$this->mask1 	= str_repeat("01111111",16);
		$this->Y	= str_repeat("\0",16);	
		$this->hbin	= $this->h2bin = array();
		for ($k=0;$k<16;$k++) 
			{
			$this->hbin[$k]=sprintf("%04b",$k);
			$this->h2bin[$this->hbin[$k]]=dechex($k);
			}
		$this->keycount=array();for ($k=0;$k<6;$k++) $this->keycount[$k]=pack("H*","0$k"."000000");
		$this->ortag="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80";
		}
  	
	function init($key,$nonce,$A="")
		{		
		// common for encryption and decryption
		
		if (strlen($key)!=32 and strlen($key)!=64)die("Key length should be 128 or 256 bits");
				
		$this->nonce     = pack("H*",$nonce);		
		$this->AESblock	 = 'AES-'.(strlen($key)*4).'-ECB';	
		
		// derive keys *****************************************************************/
		
		$keys="";for ($k=0;$k<6;$k++) $keys.=$this->keycount[$k].$this->nonce;

		$kenc		= openssl_encrypt($keys, $this->AESblock, pack("H*",$key), 1);
			  		  
		$authkey 	= substr($kenc,0,8).substr($kenc,16,8);
		$enckey 	= substr($kenc,32,8).substr($kenc,48,8);	
						
		if (strlen($key) == 64) 			  	    			  
		        $enckey.= substr($kenc,64,8).substr($kenc,80,8);	
	  			  
		$this->enckey	=$enckey;
			  		
		// Compute mulX_GHASH **********************************************************/
		 
		$binX = str_replace($this->h2bin,$this->hbin,bin2hex($authkey));				    		
		$xLSB = $binX[7];				
		$binX = "0".substr($binX,0,-1)&$this->mask1|substr($binX&$this->mask0,15);				
		if ($xLSB)
			{
			$binX = substr($binX,0,-8).(substr($binX,-8) ^ '11100001');
	
			$result="";
			foreach (array_reverse(str_split(bin2hex($this->p^$binX),16)) as $z)
				$result.=$z[1].$z[3].$z[5].$z[7].$z[9].$z[11].$z[13].$z[15];
			}
			// save cpu time: lasts 0's are irrelevant to use mulX_GHASH
				
		else   $result = implode(array_reverse(str_split($binX,8)));	
	
		$this->mulX_GHASH = rtrim($result,"0");	
		$this->sY	  = strlen($this->mulX_GHASH)-1;
		
		// Siv_Pad A  ******************************************************************/
						
		if (ctype_xdigit($A))	
			$A     = pack("H*",$A);
			
		$this->blength = bin2hex(pack('P',strlen($A)*8));
		$this->A       = $this->siv_pad($A);		
		}
				    			
	function AES_GCM_SIV_encrypt($P)
	    	{    	
		if (ctype_xdigit($P))
			$P 	= pack("H*",$P);					
		$blocks 	= str_split($P,16);
		$n		= sizeof($blocks);
		$bl		= bin2hex(pack('P',strlen($P)*8));									
		$input  	= $this->A.$this->siv_pad($P).$this->blength.$bl;
		$tag    	= $this->siv_tag($input);							 				
		$tocipher	= $this->siv_init_counters($tag,$n-1);
		$temp 		= str_split(openssl_encrypt($tocipher, $this->AESblock, $this->enckey, 1),16);
		
		$cipher="";
	        for ($i = 0; $i < $n; $i++) 		    
		    $cipher.=$temp[$i]^$blocks[$i];		    
			
	        return $cipher.$tag;
	    	} 		    

	function AES_GCM_SIV_decrypt($C)
	    	{  
		if (ctype_xdigit($C))
			$C 	= pack("H*",$C);		
		
		$tag 	  	= substr($C,-16);						
		$blocks   	= str_split(substr($C,0,-16),16);		
		$n		= sizeof($blocks);
		$todec	 	= $this->siv_init_counters($tag,$n-1);		    		    
		$temp		= str_split(openssl_encrypt($todec, $this->AESblock, $this->enckey, 1),16);
		
		$plaintext="";
	        for ($i = 0; $i < $n; $i++) 		    
		    $plaintext.=$temp[$i]^$blocks[$i];
				    		
		// now checking auth
		
		$bl		= bin2hex(pack('P',strlen($plaintext)*8));							
		$input 		= $this->A.$this->siv_pad($plaintext).$this->blength.$bl;						
		$expected_tag 	= $this->siv_tag($input);
		
		if ($expected_tag!=$tag) echo ("Tag authentication failed");
		  		
		return $plaintext;
	    	}

	function siv_pad($m)
		{
		// max plaintext length 2**32 bits = 512 MBytes

		$s=strlen($m);
		
		if ($s==0) return;	
		
		$mod=$s%16;				
		if ($mod) $m.=str_repeat("\0",16-$mod);							
		
		return bin2hex($m);		
		}
		
	function siv_init_counters($tag,$n)
		{
		// compute all block counters

		$final_counter = $counter = $tag|$this->ortag;	
		$j=0;					
		for ($k=0;$k<$n;$k++)	
			{
			$temp=substr($counter, $j, 4);
			extract(unpack('Lcount', $temp));
			$counter = substr_replace($counter, pack('L', $count+1), $j, 4);
			$final_counter.=$counter;				
			if ($temp==pack('H*', 'ffffffff')) 
				{
				$j+=4;				
				if ($j>12) break;										
				}					
		        }	
		return $final_counter;		
		}

	function siv_tag($X)
		{
		/**
		1- Computes Polyval = gfmul($X,mulX_GHASH)
		2- Xors Polyval
		3- Encrypt result to return the tag
		http://src.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/common/crypto/modes/gcm.c#46 (Copyright 2009 Sun Microsystems, Inc.) 
		OpenSolaris “gfmul” C Function
		*/	
		
		$Uints  = unpack('P*',pack("H*",$X));				
		$binY 	= $this->mulX_GHASH;									
		$lbinY  = $this->sY;
		$sX	= sizeof($Uints);						
		$lH 	= $lL = 0;	
					
	        for($i = 1; $i < $sX; $i+=2) 	
			{
			$lH 	^= $Uints[$i];
			$lL 	^= $Uints[$i+1];
			$pH	 = $pL = 0;
													
			for($j = 0; $j < $lbinY; $j++) 
				{							 
				if ($binY[$j]) 
					 {$pH 	^=$lH;
					  $pL 	^=$lL;}
				
				$xLSB = $lH;	 				
				$lH   = ($lL << 63)|(($lH >> 1) & PHP_INT_MAX);
				$lL   = ($lL >> 1 ) 		& PHP_INT_MAX;
				if ($xLSB & 1) 
					$lL 	^= 0xe100000000000000;
				}
				
			$lH 	^=$pH;
			$lL 	^=$pL;
			}	

		// xor polyval

		$polyval 	= pack('P',$lH).pack('P',$lL);
	
		$polyval 	= substr_replace($polyval,substr($polyval,0,12)^$this->nonce,0,12);	
		$polyval[15] 	= $polyval[15]&chr(127);
		
		// tag
		
		$tag 		= openssl_encrypt($polyval, $this->AESblock, $this->enckey, 1|OPENSSL_ZERO_PADDING);
	
		return $tag;		
		}			 
	}
		
function check_AES_GCM_SIV()
	{
	/*
	https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html#rfc.status Appendix C. Test vectors
	
	computing time on x5690 PHP 7.3 x64
	
	https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json			 0.010610745 s
	
	more test vectors
	
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-128-gcm-siv.json	 0.005141024 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/aes-256-gcm-siv.json	 0.00528642  s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/authentication-1000.json	 1.784798668 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/encryption-1000.json	 1.884995769 s
	https://raw.githubusercontent.com/Metalnem/aes-gcm-siv/master/src/Cryptography.Tests/Vectors/random-keys-10000.json	 1.092802567 s
	
	Encryption time average 100 µs	(16 byte block)	
	*/
	
	$x=new AES_GCM_SIV;$n=0;
		
	if (!function_Exists("hrtime"))
		{function hrtime($bool) {return microtime($bool)*1000000000;}} 
							
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json"));
	
	$t=hrtime(true);
	foreach ($testvectors->AES_GCM_SIV_tests  as $test)
		{
		echo "----------------------------------------TEST CASE ".++$n."\n\n";		
		echo "------------------------------ivSize ".$test->ivSize." keySize ".$test->keySize." tagSize ".$test->tagSize."\n\n";
		
		$text	= $test->msg;
		$aad	= $test->aad;	
		$key	= $test->key;
		$nonce	= $test->iv;
		$tag	= $test->tag;
		$result	= $test->ct;
							
		echo "Plaintext 		".$text."\n";
		echo "AAD       		".$aad."\n";
		echo "Key       		".$key."\n";
		echo "Nonce     		".$nonce."\n";			
		echo "Tag       		".$tag."\n";
		echo "Result    		".$result."\n\n";
		
		$x->init($key,$nonce,$aad);							
		$C = $x->AES_GCM_SIV_encrypt($text);
		$D = $x->AES_GCM_SIV_decrypt($C);
			
		$ctag = substr($C,-16);
		
		echo "Computed tag 	".bin2hex($ctag)."\n";
		echo "Computed result ".bin2hex($C)."\n";				
		echo "Computed dcrypt ".bin2hex($D)."\n\n"; 		
		if (bin2hex($C)!=$result)die("failed");							
		}
	echo ((hrtime(true)-$t)/1000000000)." s\n";
	}
check_AES_GCM_SIV();
