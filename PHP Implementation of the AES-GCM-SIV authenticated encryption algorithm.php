<?php
/**
*  Copyright I-2019 denobisipsis
*
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of the
*  License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*  General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
*  02111-1307 USA
*
#AES-GCM-SIV code with each step explained for PHP 5 & 7

#USAGE for AES-GCM-SIV

$text	= "Hello World";
$A	= "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21";
$key	= "f901cfe8a69615a93fdf7a98cad48179";
$nonce	= "6245709fb18853f68d833640";

$x=new AES_GCM_SIV;				
$x->init($key,$nonce);

$C = $x->AES_GCM_SIV_encrypt($text,$A);

$P = $x->AES_GCM_SIV_decrypt($C,$A);

	THERE IS A VECTOR-TEST to validate THIS AES-GCM-SIV, SIMPLY RUN check_AES_GCM_SIV()
	
Support modes:

for AEAD_AES_128_GCM_SIV 

https://eprint.iacr.org/2017/168.pdf

https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html
*/

class AES_GCM_SIV
	{	
	public $nonce,$K,$block_bits,$p,$R,$mask0,$mask1,$H; 

	function __construct($p="",$R="",$mask0="",$maks1="",$H="",$Y="")
		{
		$this->p 	= str_repeat("0",128);
		$this->R 	= hexdec("e1");
		$this->mask0 	= str_repeat(sprintf("%08b",1),16);
		$this->mask1 	= str_repeat("01111111",16);
		$this->H	= pack("H*","40000000000000000000000000000000");
		$this->Y	= str_repeat("\0",16);				
		}
  	
	function init($K,$nonce)
		{
		if (strlen($K)!=32 and strlen($K)!=64)
			die("Key length should be 128 or 256 bits");

		$this->K     = $K;
		$this->nonce = $nonce;
		
		$this->block_bits=strlen($K)*4;				
		}
				    			
	function AES_GCM_SIV_encrypt($P,$A="")
	    	{  		
		$nonce = $this->nonce;
		$key   = $this->K;
						
		list ($authkey,$enckey) = $this->derive_keys($key,$nonce);

		if (ctype_xdigit($P)) $P = pack("H*",$P);
		if (ctype_xdigit($A)) $A = pack("H*",$A);
				
		$P0 = $P;
				
		list ($blength,$A) = $this->siv_pad($A);		
		list ($bl,$P) 	   = $this->siv_pad($P);
					
		$input = bin2hex($A.$P).$blength.$bl;				
		$X   = $authkey.pack("H*",$input);	
  		$Y   = $this->siv_xor_nonce($this->siv_polyval($X));						
		$tag = $this->siv_tag($Y,$enckey);

		$cblock = $this->siv_init_counter($tag); 
		$blocks = str_split($P0,16);		
		$cipher = "";		
		
	        for ($i = 0; $i < sizeof($blocks); $i++) 
		    {
		    $cipher.=openssl_encrypt($cblock, 'AES-'.$this->block_bits.'-ECB', $enckey, OPENSSL_RAW_DATA)^$blocks[$i];
		    $cblock = $this->siv_inc($cblock);  
		    }
		
	        return bin2hex($cipher).$tag;
	    	} 		    

	function AES_GCM_SIV_decrypt($C,$A)
	    	{  
		$nonce=$this->nonce;
		$key  =$this->K;
		  						
		list ($authkey,$enckey) = $this->derive_keys($key,$nonce);
				
		if (ctype_xdigit($C))  $C = pack("H*",$C);
		if (ctype_xdigit($A))  $A = pack("H*",$A);
		
		$tag = bin2hex(substr($C,-16));						
		$C   = str_split(substr($C,0,-16),16);
						
		$cblock = $this->siv_init_counter($tag);										
		$plaintext = "";
				
	        for ($i = 0; $i < sizeof($C); $i++) 
		    {	    
		    $plaintext.=openssl_encrypt($cblock, 'AES-'.$this->block_bits.'-ECB', $enckey, OPENSSL_RAW_DATA)^$C[$i];		    
		    $cblock = $this->siv_inc($cblock);  
		    }
		 
		// now checking auth
		 
		list ($blength,$A) = $this->siv_pad($A);		
		list ($bl,$C) 	   = $this->siv_pad($plaintext);
					
		$input = bin2hex($A.$C).$blength.$bl;		
		$X     = $authkey.pack("H*",$input);			
									
		$S_s   = $this->siv_xor_nonce($this->siv_polyval($X));						
		$expected_tag = $this->siv_tag($S_s,$enckey);
		
		if ($expected_tag!=$tag) 
		    die("fail");
		  		
		return bin2hex($plaintext);
	    	}
		    
	function derive_keys($key, $nonce) 
		{
		  $len = strlen($key);
		  
		  $keys="";for ($k=0;$k<(($len+1)*3)/32;$k++) $keys.=pack("H*","0$k"."000000".$nonce);					  
		  $kenc=openssl_encrypt($keys, 'AES-'.$this->block_bits.'-ECB', pack("H*",$key), OPENSSL_RAW_DATA);
		  
		  $authkey 	= substr($kenc,0,8).substr($kenc,16,8);
		  $enckey 	= substr($kenc,32,8).substr($kenc,48,8);	
						
		  if ($len == 64) 			  	    			  
		        $enckey.= substr($kenc,64,8).substr($kenc,80,8);
		  	  			  
		  return [$authkey, $enckey];
		}

	function siv_pad($m)
		{
		// max plaintext length 2**32 bits = 512 MBytes
		
		$blength=bin2hex(strrev(pack('N',strlen($m)*8)))."00000000";
			
		$mod=strlen($m)%16;
						
		if ($mod) $m.=str_repeat("\x0",16-$mod);							
			
		return [$blength,$m];		
		}
		
	function siv_polyval($X)
		{
		/**		  
		POLYVAL works modulo x^128 + x^127 + x^126 + x^121 + 1
					    
		Now GHASH and POLYVAL can be defined in terms of one another:

		   Let mulX_GHASH be a function that takes a 16-byte string, converts it
		   		   to an element of GHASH's field using GHASH's convention, multiplies
		   		   it by x and converts back to a string
				      
		   Then,
		   		
		   POLYVAL(H, X_1, ..., X_n) =
		   ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ...,
		   ByteReverse(X_n)))
		   
		   GHASH(mulX_GHASH(ByteReverse(H)) is $H = $this->gf128($Y ^ $X[$nblocks],$H);
		   
		   the rest is the do loop
		*/		
		$Y = $this->Y; 						
		$X=str_split(strrev($X) , 16);				
	        $nblocks = sizeof($X) - 1;		
		$H = $this->gf128($Y ^ $X[$nblocks],$this->H);
		
	        do {$Y = $this->gf128($Y ^ $X[$nblocks-1] , $H);} while (--$nblocks>0);	    

  		return strrev($Y);		
		}
		
	function siv_tag($Y,$enckey)
		{
		return substr(bin2hex(openssl_encrypt($Y, 'AES-'.$this->block_bits.'-ECB', $enckey, OPENSSL_RAW_DATA)),0,32);		
		}
		
	function siv_xor_nonce($Y)
		{	
		$nonce=pack("H*",$this->nonce);		
		
		$Y=substr_replace($Y,substr($Y,0,12)^$nonce,0,12);
		
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
		        $temp = strrev(substr($counter, -$j, 4));
	                extract(unpack('Ncount', $temp));		
	                $long=pack('N', $count+1);
			$counter = substr_replace($counter, strrev($long), -$j, 4);			
			if ($temp!=0xFFFFFFFF and $temp!=0x7FFFFFFF) return $counter;				
		        }
		return $counter;				
		}
						
		/**
		6.3 Multiplication Operation on Blocks 
		
		https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf#11-12
		
		Algorithm 1: X ?Y
		Input:
		blocks X, Y.
		Output:
		block X ?Y.
		
		Steps:
		1. Let x0x1...x127 denote the sequence of bits in X.
		2. Let Z0 = 0128 and V0 = Y.
		3. For i = 0 to 127, calculate blocks Zi+1 and Vi+1 as follows:
	
			Zi+1 =
		 		if xi = 0;
					Zi
		 		if xi =1.
				 	Zi ^ Vi
	
			Vi+1 = 
				Vi >>1 		if LSB1(Vi) = 0;
		 		Vi >>1 ^ R 	if LSB1(Vi) = 1.
	
		
		4. Return Z128.
		
		As you see is better
			Zi+1 =  Zi ^ Vi		if xi =1
			Vi+1 = 
				Vi >>1 		
		 		Vi ^ R 		if LSB1(Vi) = 1
				 
		for s=1 special case
		
		Constant R dependes on algebraical analysis.
		See http://www.hpl.hp.com/techreports/98/HPL-98-135.pdf
		
		A table of low-weight irreducible polynomials over the
		finite field F2 is presented. For each integer n in the
		range 2 = n = 10,000, a binary irreducible polynomial
		f(x) of degree n and minimum posible weight is listed.
		Among those of minimum weight, the polynomial
		listed is such that the degree of f(x) – x
		n is lowest
		(similarly, subsequent lower degrees are minimized in
		case of ties). 
					
		- for 128 bits 128,7,2,1 -> x^128 + x^7 + x^2 + x^1 + 1 
		
			generator for the isomorphism of GF(2^128)
			equivalent to the bit vector (1 || 120"0" || 10000111). (only exponents below 8)
			(
			Where each bit reflects a power of "x" appearing in the polynomial.
			i.e.: b7-b6-b5-b4 b3-b2-b1-b0
			      1   0  0  0  0  1  1  1
			)
			
			10000111 is 0xE1 (little-endian fashion) or 0x87 (big-endian)
			
		- for 8 bits     8,4,3,1 -> x^8   + x^4 + x^3 + x^1 + 1 (1=x^0)
			generator for the isomorphism of GF(2^8)
			(
			i.e.: b7-b6-b5-b4 b3-b2-b1-b0
			      0   0  0  1  1  0  1  1
			)
			
			00011011 is 0xD8 (little-endian fashion) or 0x1B (big-endian)	
			
		The main process equals to 
		
				        $X[$s]>>=1;							
	 			        for($j=1;$j<=$s;$j++)
	 			            {			
	 			            if ($X[$s-$j] & 1)					    	 
	 					    $X[$s-$j+1] |= 0x80;
	 			            $X[$s-$j]>>=1;          
	 			            }
					     
				but as implemented here is faster
				
				explanans:
				
				1- "0".substr($binX,0,-1)  this equals to $binX >> 1
				2- & mask1 flip first bit after shifting (must be 0)
				3- substr($binX&$mask0,15) this saves highbit from all uint8 and alineates from 15 => if ($X[$s-$j] & 1) $X[$s-$j+1] |= 0x80;
				4- make "or" from the 2 results above  
				
				http://chris-wood.github.io/2016/12/25/GCM-SIV.html have a python implementation with theoretical
				
				    ''' dot operation using the irreducible polynomials R and Ri(=R^{-1}).
				    We convert the input elements to their proper field representation
				    for the standard multiplication algorithm to work as is.
				    Compute: a * b * Ri
				    R    = x^128 + x^127 + x^126 + x^121 + 1 = 0x010000000000000000000000000000C2
				    R^-1 = x^127 + x^124 + x^121 + x^114 + 1 = 0x01000000000000000000000000000492
				    '''
				
				Then, dot(a,b)=$this->siv_polyval($X) (X=a.b)
				
				My implementation (gf128 uses standard R = 0xE1)
				 		
					$H  = pack("H*","40000000000000000000000000000000");
									
					$X=str_split(strrev($X) , 16);	
					
					a = $X[1]
					b = $X[0]			
				
					$H = $this->gf128(a , $H);
					
				        $Y = $this->gf128(b , $H);	    
					
					dot(a,b) = bin2hex(strrev($Y));
				
				but original dot appears as
				
				    R  = convert(0x010000000000000000000000000000C2)
				    Ri = convert(0x01000000000000000000000000000492)
				    
				    a_poly = convert(to_hex(a))
				    b_poly = convert(to_hex(b))
				    
				    ab     = gf128_mul(a_poly, b_poly, R)
				    
				    dot(a,b) = convert(gf128_mul(ab, Ri, R))	
		*/
			
	function gf128($X,$Y) 
		{		
		$Y = str_split($Y);		
		$X = array_reverse(array_values(unpack("C*",$X)));

		$p = $this->p;				
		$R = $this->R; // 0xe1
		
		// masks to fast shifting, oring and anding
		
		$mask0 = $this->mask0;
		$mask1 = $this->mask1;

		// Work X in binary-string form binX
		
		$binX = implode(array_map(function($v) {return sprintf('%08b', $v);},$X));
			
		for($i = 0; $i < 16; $i++) 
			{			
			$f = ord($Y[$i]);						
			for ($m = 0; $m < 8; $m++)
				{				 
				if ($f & 0x80) 
					$p^=$binX;
								 
				$xLSB = $binX[7];				
				$binX = "0".substr($binX,0,-1)&$mask1|substr($binX&$mask0,15);				
				if ($xLSB)
					$binX = substr($binX,0,-8).decbin(bindec(substr($binX,-8)) ^ $R);
			        $f <<=1;
			        }				 			
			}
		
		// restore pure binary form of p (=result)
		
		$result="";foreach (str_split(bin2hex($p),2) as $z) $result.=$z[1];

		return strrev(implode(array_map(function($v) {return chr(bindec($v));},str_split($result,8))));	
		}		 
	}

function check_AES_GCM_SIV()
	{	
	// https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html#rfc.status Appendix C. Test vectors
	
	ECHO "AES GCM SIV test vectors from https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html \n\n";
	
	
	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json"));

	$x=new AES_GCM_SIV;
	
	if (!function_Exists("hrtime"))
		{
		function hrtime($bool) {return microtime($bool)*1000000000;}
		} 
	$ntest=array(1,2,3,25,33,44,48,49,50);		
	$t=hrtime(true);
	foreach ($testvectors->AES_GCM_SIV_tests as $test)
		{	
	
		echo "----------------------------------------TEST CASE ".$test->tcId."\n\n";
		
		echo "---------------------------------------- ivSize ".$test->ivSize." keySize ".$test->keySize." tagSize ".$test->tagSize."\n\n";
				
		$text	= $test->msg;
		$A	= $test->aad;
		$key	= $test->key;
		$nonce	= $test->iv;
		$tag	= $test->tag;
		$result	= $test->ct;
							
	/**/	echo "Plaintext 		".$text."\n";
		echo "AAD       		".$A."\n";
		echo "Key       		".$key."\n";
		echo "Nonce     		".$nonce."\n";			
		echo "Tag       		".$tag."\n";
		echo "Result    		".$result."\n\n";
		
		$x->init($key,$nonce);					
		
		$t1=hrtime(true);	
		$C=$x->AES_GCM_SIV_encrypt($text,$A);
		echo "Encryption takes ".((hrtime(true)-$t1)/1000000)." ms\n";	
			
		$ctag = substr($C,-32);
		$cres = $C;
		
		echo "Computed tag 	".$ctag."\n";
		echo "Computed result ".$cres."\n";
				
		echo "Computed dcrypt ".$x->AES_GCM_SIV_decrypt($C,$A)."\n";/**/
		
		//$P = $x->AES_GCM_SIV_decrypt($C,$A);
				
		if ($ctag!=$tag or $cres!=$result)die("failed");
															
		}
	echo ((hrtime(true)-$t)/1000000)." ms";	
	}

check_AES_GCM_SIV();
