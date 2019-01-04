<?
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
AES-GCM & AES-GCM-SIV code with each step explained

ECB is computed with openssl internally

USAGE for AES-GCM-SIV

	$text	= "Hello World";
	$A	= "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21";
	$key	= "f901cfe8a69615a93fdf7a98cad48179";
	$nonce	= "6245709fb18853f68d833640";
	
	$x=new AES_GCM_SIV;				
	$x->init($key,$nonce);
	
	$C = $x->AES_GCM_SIV_encrypt($text,$A);
	
	$P = $x->AES_GCM_SIV_decrypt($C,$A);

		THERE IS A VECTOR-TEST to validate THIS AES-GCM-SIV, SIMPLY RUN check_AES_GCM_SIV()

USAGE for AES-GCM

	$x=new AES_GCM_SIV; 
	
	$K = 'feffe9928665731c6d6a8f9467308308feffe9928665731cfeffe9928665731c6d6a8f9467308308feffe9928665731c';

	// The data to encrypt (can be null for authentication)
	$P = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39';

	// Additional Authenticated Data
	$A = 'feedfacedeadbeeffeedfacedeadbeefabaddad2';

	// Initialization Vector
	$IV = 'cafebabefacedbaddecaf888';

	$x->init($K,$IV);
	
	// $C is the encrypted data ($C is null if $P is null)
	// $T is the associated tag

	list($C, $T) = $x->AES_GCM_encrypt($P, $A, "",128);

	list($P, $T) = $x->AES_GCM_decrypt($C, $A, $T,128);
	
		THERE IS A VECTOR-TEST to validate THIS AES-GCM, SIMPLY RUN testvectors_gcm()

Support modes:

	- AES Galois Counter Mode (GCM)
	- AES Galois Counter Mode nonce misuse-resistant (GCM-SIV)
*/

class AES_GCM_SIV
	{
	var $nonce;
	var $K;
	var $block_bits;
	
	function init($K,$nonce)
		{
		if (strlen($K)!=32 and strlen($K)!=64)
			die("Key length should be 128 or 256 bits");

		$this->K     = $K;
		$this->nonce = $nonce;
		
		$this->block_bits=strlen($K)*4;				
		}

	/**
	GCM MODE
	
	Recommendation for Block
	Cipher Modes of Operation:
	Galois/Counter Mode (GCM)
	and GMAC
	
	https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	
	Freely adopted & modified in part the script https://github.com/Spomky-Labs/php-aes-gcm
	
	Specially, the GMUL function.	
	*/
			
	function AES_GCM_encrypt($P = null, $A = null, $T = null, $tag_length = 128)
	    	{
		/**
		Same for decrypting with the T value
		*/
		
		$K 	= $this->K;
		$nonce 	= $this->nonce;
		
		if (ctype_xdigit($P)) 		$P=pack("H*",$P);
		if (ctype_xdigit($A)) 		$A=pack("H*",$A);
		if (ctype_xdigit($K)) 		$K=pack("H*",$K);
		if (ctype_xdigit($nonce)) 	$nonce=pack("H*",$nonce);
		
		$T1 = $C2 = "";		
		$key_length = mb_strlen($K, '8bit') * 8;
					
		if (!in_Array($tag_length, [128, 120, 112, 104, 96])) print_r('Invalid tag length. Supported values are: 128, 120, 112, 104 and 96.');	
				
	        list($J0, $v, $a_len_padding, $H) = $this->GCMSETUP($K, $key_length, $nonce, $A);						
	        $C = $C3 = $this->GCTR($K, $key_length, $this->Inc(32, $J0), $P);
		
		if ($T!=null) {$C=$C2=$P;$T1=$T=pack("H*",$T);}
		
	        $u = $this->calcVector($C);		
	        $c_len_padding = $this->addPadding($C);	
	        $S = $this->Hash($H, $A.str_pad('', $v / 8, "\0").$C.str_pad('', $u / 8, "\0").$a_len_padding.$c_len_padding);
		
		if ($T==null) $C = bin2hex($C); else $C = bin2hex($C2);
		
	        $T = $this->SB($tag_length, $this->GCTR($K, $key_length, $J0, $S));
		
		if ($T1!=$T and $C2) print_r('Unable to decrypt or to verify the tag.');		
		
		if ($C2) $C = $C3;
		
	        return [$C, bin2hex($T)];
	    	}
	
	function AES_GCM_decrypt($C  = null, $A = null, $T = null, $tag_length = 128)
		{
		return $this->AES_GCM_encrypt($C, $A, $T, $tag_length);
		}
				        
	function GCMSETUP($K, $key_length, $IV, $A)
		{	 	
		$H=substr(openssl_encrypt(str_repeat("\0", 16), 'AES-'.$this->block_bits.'-ECB', $K, OPENSSL_RAW_DATA),0,16);
		
	        $iv_len = $this->gLength($IV);
	
	        if (96 === $iv_len) 
	            	$J0 = $IV.pack('H*', '00000001');
	        else 
			{
			$s = $this->calcVector($IV);
			if (($s + 64) % 8!=0) print_r('Unable to decrypt or to verify the tag.');
			
			$packed_iv_len = pack('N', $iv_len);
			$iv_len_padding = str_pad($packed_iv_len, 8, "\0", STR_PAD_LEFT);
			$hash_X = $IV.str_pad('', ($s + 64) / 8, "\0").$iv_len_padding;
			$J0 = $this->Hash($H, $hash_X);
	        	}
			
	        $v = $this->calcVector($A);		
	        $a_len_padding = $this->addPadding($A);

	        return [$J0, $v, $a_len_padding, $H];
		}
		    
	function calcVector($value)
	    	{return (128 * ceil($this->gLength($value) / 128)) - $this->gLength($value);}
    
	function addPadding($value)
	    	{return str_pad(pack('N', $this->gLength($value)), 8, "\0", STR_PAD_LEFT);}
	
	function gLength($x)
	    	{return strlen(bin2hex($x)) * 4;}
	    
	function SB($s, $X, $init=0)
	    	{
		/** 
		bit string consisting of the s RIGHT-most bits of the bit string X		
		*/
		
		$s=$s/8;			
	        return mb_substr($X, $init, $s, '8bit');
	    	}
	
	function Inc($s_bits, $x)
	    	{
		/**
		output of incrementing the right-most s bits of the bit string X,
		regarded as the binary representation of an integer, by 1 modulo 2s
		
		initial counter block ICB
		*/
	        $lsb = mb_substr($x, -($s_bits/8), $s_bits/8, '8bit');								
		$X = @array_shift(unpack("L",strrev($lsb))) + 1;
	        return $this->SB($this->gLength($x) - $s_bits, $x).pack('N', $X);
	    	}
			    	           				
	function GCTR($K, $key_length, $ICB, $X)
	    	{
		/**
		output of the GCTR function for a given block cipher with key K
		applied to the bit string X with an initial counter block ICB		
		*/

		$X=str_split($X,16);	   			
	        $Y = "";
	        $CB = $ICB;
	        for ($i = 0; $i < sizeof($X); $i++)
			{		
			$Y.= $X[$i] ^ openssl_encrypt($CB, 'AES-'.$this->block_bits.'-ECB', $K, OPENSSL_RAW_DATA);	            	
			$CB = $this->Inc(32, $CB);
			}	        	
			
	        return $Y;
	    	}

	function Hash($H, $X)
	    	{
		/**
		output of the GHASH function under the hash subkey H applied to
		the bit string X
		
		$H is the hash subkey
		$X bit string such that len(X) = 128m for some positive integer m
		*/
		
	        $Y = str_repeat("\0", 16);
		$X=str_split(($X),16);
	        for ($i = 0; $i < sizeof($X); $i++) 
	            $Y = $this->gf128($H,$Y ^ $X[$i]);		
	   	        	
	        return ($Y);
	    	} 

/**		  
for AEAD_AES_128_GCM_SIV 

https://eprint.iacr.org/2017/168.pdf

https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html
*/
				    			
	function AES_GCM_SIV_encrypt($P,$A="")
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
		*/
  		
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
		$Y = str_pad('', 16, "\0");		
		$H  = pack("H*","40000000000000000000000000000000");		
		$X=str_split(strrev($X) , 16);		
	        $nblocks = sizeof($X) - 1;		
		$H = $this->gf128($Y ^ $X[$nblocks],$H);
		
	        for ($i = $nblocks-1; $i >= 0; $i--) 
			$Y = $this->gf128($Y ^ $X[$i] , $H);		    
		    	
  		return strrev($Y);		
		}
		
	function siv_tag($Y,$enckey)
		{		
		return substr(bin2hex(openssl_encrypt($Y, 'AES-'.$this->block_bits.'-ECB', $enckey, OPENSSL_RAW_DATA)),0,32);		
		}
		
	function siv_xor_nonce($Y)
		{		
		$nonce=str_split(pack("H*",$this->nonce));		

		for ($i = 0; $i < 12; $i++) 	
			$Y[$i] = $Y[$i] ^ $nonce[$i];			   
		
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
				
	function gf128($X,$Y) 
		{		
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
		listed is such that the degree of f(x)  x
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
		*/		
		
		$Y=str_split($Y);
		$X=array_values(unpack("C*",$X));		
		$s=sizeof($Y)-1;
		$p=str_split(str_repeat("0",$s+1)); 			
		for($i = 0; $i <=$s; $i++) 
			{			
			$f=ord($Y[$i]);			
			for ($m=0;$m<8;$m++)
				{	 
				if ($f & 0x80)	for($j=0;$j<=$s;$j++) $p[$j]^=$X[$j];							
				$LSB=$X[$s];									
				$X[$s]>>=1;							
			        for($j=1;$j<=$s;$j++)
			            {			
			            if ($X[$s-$j] & 1)					    	 
					    $X[$s-$j+1] |= 0x80;
			            $X[$s-$j]>>=1;          
			            }				    
				if ($LSB & 1)	$X[0]^=0xe1;									
			        $f<<=1;
			        }			
			}
		return implode(array_map('chr', $p));
		}
												
	function pad($text='')
		{
		$length = strlen($text);
		$padding =  16 - ($length  % 16 );
		$text = str_pad($text,  $length + $padding, chr($padding) );
		return $text;
		}
		
     	function unpad($text='')
		{			
		$padded = (int) ord($text[strlen($text)-1]);
		$padded = ($padded > 16 ? 16 : $padded);
		$text = substr($text,0,strlen($text)-$padded);
		return rtrim($text, "\0"); // TO AVOID BAD MCRYPT PADDING		
		}		 
	}

function check_AES_GCM_SIV()
	{	
	// https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html#rfc.status Appendix C. Test vectors
	
	ECHO "AES GCM SIV test vectors from https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html \n\n";

	$testvectors=json_Decode(file_get_contents("https://raw.githubusercontent.com/denobisipsis/PHP_AES-GCM-SIV/master/aes_gcm_siv_test_draft.09.json"));

	$x=new AES_GCM_SIV;

	$t=time();
	
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
							
		echo "Plaintext 		".$text."\n";
		echo "AAD       		".$A."\n";
		echo "Key       		".$key."\n";
		echo "Nonce     		".$nonce."\n";			
		echo "Tag       		".$tag."\n";
		echo "Result    		".$result."\n\n";
		
		$x->init($key,$nonce);				
		$C = $x->AES_GCM_SIV_encrypt($text,$A);
		
		$ctag = substr($C,-32);
		$cres = $C;
		
		echo "Computed tag 	".$ctag."\n";
		echo "Computed result ".$cres."\n";
		echo "Computed dcrypt ".$x->AES_GCM_SIV_decrypt($C,$A)."\n\n";
		
		if ($ctag!=$tag or $cres!=$result)
			die("failed");								
		}

	echo time()-$t;
	}

check_AES_GCM_SIV();

function testvectors_gcm()
{	
# AES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

$AES_GCM_TEST_VECTORS=
"AES-128-GCM:00000000000000000000000000000000:000000000000000000000000::::58e2fccefa7e3061367f1d57a4e7455a
AES-128-GCM:00000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78::ab6e47d42cec13bdf53a67b21257bddf
AES-128-GCM:feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985::4d5c2af327cd64a62cf35abd2ba6fab4
AES-128-GCM:feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091:feedfacedeadbeeffeedfacedeadbeefabaddad2:5bc94fbc3221a5db94fae95ae7121a47
AES-128-GCM:feffe9928665731c6d6a8f9467308308:cafebabefacedbad:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598:feedfacedeadbeeffeedfacedeadbeefabaddad2:3612d2e79e3b0785561be14aaca2fccb
AES-128-GCM:feffe9928665731c6d6a8f9467308308:9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5:feedfacedeadbeeffeedfacedeadbeefabaddad2:619cc5aefffe0bfa462af43c1699d050
AES-256-GCM:0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000::::530f8afbc74536b9a963b4f1c4cb738b
AES-256-GCM:0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:cea7403d4d606b6e074ec5d3baf39d18::d0d1c8a799996bf0265b98b5d48ab919
AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad::b094dac5d93471bdec1a502270e3cc6c
AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662:feedfacedeadbeeffeedfacedeadbeefabaddad2:76fc6ece0f4e1768cddf8853bb2d551b
AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbad:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f:feedfacedeadbeeffeedfacedeadbeefabaddad2:3a337dbf46a792c45e454913fe2ea8f2
AES-256-GCM:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39:5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f:feedfacedeadbeeffeedfacedeadbeefabaddad2:a44a8266ee1c8eb0c8b5d4cf5ae9f19a
AES-128-GCM:00000000000000000000000000000000:000000000000000000000000:::d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad:5fea793a2d6f974d37e68e0cb8ff9492
AES-128-GCM:00000000000000000000000000000000:000000000000000000000000:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0::9dd0a376b08e40eb00c35f29f9ea61a4
AES-128-GCM:00000000000000000000000000000000:000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8ee35616f7124a9d5270291::98885a3a22bd4742fe7b72172193b163
AES-128-GCM:00000000000000000000000000000000:000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8ee35616f7124a9d527029195b84d1b96c690ff2f2de30bf2ec89e00253786e126504f0dab90c48a30321de3345e6b0461e7c9e6c6b7afedde83f40::cac45f60e31efd3b5a43b98a22ce1aa1
AES-128-GCM:00000000000000000000000000000000:ffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:56b3373ca9ef6e4a2b64fe1e9a17b61425f10d47a75a5fce13efc6bc784af24f4141bdd48cf7c770887afd573cca5418a9aeffcd7c5ceddfc6a78397b9a85b499da558257267caab2ad0b23ca476a53cb17fb41c4b8b475cb4f3f7165094c229c9e8c4dc0a2a5ff1903e501511221376a1cdb8364c5061a20cae74bc4acd76ceb0abc9fd3217ef9f8c90be402ddf6d8697f4f880dff15bfb7a6b28241ec8fe183c2d59e3f9dfff653c7126f0acb9e64211f42bae12af462b1070bef1ab5e3606::566f8ef683078bfdeeffa869d751a017
AES-128-GCM:843ffcf5d2b72694d19ed01d01249412:dbcca32ebf9b804617c3aa9e:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f:6268c6fa2a80b2d137467f092f657ac04d89be2beaa623d61b5a868c8f03ff95d3dcee23ad2f1ab3a6c80eaf4b140eb05de3457f0fbc111a6b43d0763aa422a3013cf1dc37fe417d1fbfc449b75d4cc5:00000000000000000000000000000000101112131415161718191a1b1c1d1e1f:3b629ccfbc1119b7319e1dce2cd6fd6d";


$x=new AES_GCM_SIV; 

$n=0;

ECHO "\n\nAES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf \n\n";

foreach (explode("\n",$AES_GCM_TEST_VECTORS) as $TVECTOR)
	{
	ECHO "..................................TEST CASE ".++$n."\n\n";
	$TVECTOR=array_slice(EXPLODE(':',$TVECTOR),1);
	$K=$TVECTOR[0];
	$IV=$TVECTOR[1];
	$P=$TVECTOR[2];
	$A=$TVECTOR[4];
	$CTEST=$TVECTOR[3];
	$TTEST=$TVECTOR[5];
	
	ECHO "K $K\nP $P\nIV $IV\nA $A\nVALID C $CTEST\nVALID T $TTEST\n\n";
		
	$x->init($K,$IV);
	
	list($C, $T) = $x->AES_GCM_encrypt($P, $A, "",128);
	
	echo "COMPUTED C $C\nCOMPUTED T $T\n\n";
	
	list($P, $T) = $x->AES_GCM_decrypt($C, $A, $T,128);

	echo "DECRYPTED P ".bin2hex($P)."\nDECRYPTED T $T\n\n";	
	
		if ($C!=$CTEST or $T!=$TTEST)
			die("failed");	
	}
}

testvectors_gcm();	
