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
Pure PHP Rijndael/AES-GCM-SIV code with each step explained

USAGE for AES-GCM

	$x=new AES_GCM_SIV; 
	
	$K = 'feffe9928665731c6d6a8f9467308308feffe9928665731cfeffe9928665731c6d6a8f9467308308feffe9928665731c';

	// The data to encrypt (can be null for authentication)
	$P = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39';

	// Additional Authenticated Data
	$A = 'feedfacedeadbeeffeedfacedeadbeefabaddad2';

	// Initialization Vector
	$IV = 'cafebabefacedbaddecaf888';

	$x->init("gcm",$K,$IV,16);
	
	// $C is the encrypted data ($C is null if $P is null)
	// $T is the associated tag

	list($C, $T) = $x->encrypt($P, $A, "",128);

	list($P, $T) = $x->decrypt($C, $A, $T,128);
	
THERE IS A VECTOR-TEST to validate THIS AES-GCM, SIMPLY RUN testvectors_gcm()

USAGE for AES-GCM-SIV

	$text	= "Hello World";
	$A	= "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21";
	$key	= "f901cfe8a69615a93fdf7a98cad48179";
	$nonce	= "6245709fb18853f68d833640";
	
	$x=new AES_GCM_SIV;				
	$x->init("gcm",$key,$nonce,16);
	
	$C = $x->AES_GCM_SIV_encrypt($text,$A);
	
	$P = $x->AES_GCM_SIV_decrypt($C,$A);

THERE IS A VECTOR-TEST to validate THIS AES-GCM-SIV, SIMPLY RUN check_AES_GCM_SIV()

Support modes:

GCM: AES Galois Counter Mode
GCM: SIV-AES Galois Counter Mode nonce misuse-resistant

*/
class AES_GCM_SIV
	{	
	var $sbox;
	var $Nr;
	var $Nk;
	var $keys;
	var $iv;
	var $iv_ctr;
	var $iv_gcm;
	var $Nb;
	var $c;
	var $block_size;
	var $mode;
	var $gcm_tag_length;
	var $K;
	var $key;
	
	function init($mode='gcm',$key,$iv="",$block_size=16)
		{
		$mode=strtolower($mode);
						
		if (!ctype_xdigit($key) and $mode!="gcm") $key=bin2hex($key);
		if (!ctype_xdigit($iv) and $mode!="gcm")  $iv=bin2hex($iv);
		
		if ((strlen($key)%4)!=0)
			die("Key length should be 16,20,24,28 or 32 bytes");
		elseif (strlen($key)<32 or strlen($key)>128)
			die("Key length should be 16,20,24,28 or 32 bytes");
		
		$this->key=$key;
		$this->block_size = $block_size;
		$this->mode=$mode;
		$this->iv_gcm = $iv;				
		
		/**
		Iv is padded to block_size except for GCM mode	
		*/
				
		if ($iv!="")
			if (strlen($iv)!=$block_size*2 and $mode!="gcm")				
				$iv=str_pad(substr($iv, 0, $this->block_size*2), $this->block_size*2, "00"); 
						
		$this->iv = $iv;

		if ($mode=="gcm") 
			{
			$this->K  = pack("H*",$key);
			$this->iv = pack("H*",$iv);			
			return;
			}
		
		if ($this->sbox=="")							
			$this->generatesbox();	
		
		$this->Nb = $block_size/4;
		$this->Nk = strlen($key)/8;
		$this->Nr = max($this->Nk, $this->Nb) + 6;
						
		$this->key_expansion($key);	
				
		// COLUMNS SHIFTING 
		
	        switch ($this->Nb) {
	            case 4:
	            case 5:
	            case 6:
	                $this->c = 4; // 128,160,192 BITS
	                break;
	            case 7:
	                $this->c = 2; // 224
	                break;
	            case 8:
	                $this->c = 1; // 256
	        }		
		
		if ($this->gcm_tag_length) $mode="gcm";	
		}
	
	function rOTL8($x,$shift) 
		{
		// FOR AFFINE TRANSFORMATION
		return ($x << $shift) | ($x >> (8 - $shift));}
	
	function generatesbox() 
		{		
		$p = $q = 1;
		
		/** LOOP INVARIANT: p * q == 1 IN THE GALOIS FIELD */
		
		do {
			/** MULTIPLY p BY 3 */
			
			$p ^= $this->multiply($p);
	
			/** DIVIDE q BY 3 = * 0xf6) */
			
			$q^= $q << 1;
			$q^= $q << 2;
			$q^= $q << 4;
			$q^= $q & 0x80 ? 0x09 : 0;
			
			$q %=256;
			
			/** AFFINE TRANSFORMATION */
			
			$xformed = ($q ^ $this->rOTL8($q, 1) ^ $this->rOTL8($q, 2) ^ $this->rOTL8($q, 3) ^ $this->rOTL8($q, 4)) % 256;
	
			$sbox[$p] = $xformed ^ 0x63;
			
		} while ($p != 1);
	
		/** 0 HAS NO INVERSE */
		
		$sbox[0] = 0x63;
		
		$this->sbox=$sbox;
		}
						
	function sub_byte($byte,$xor="")
		{
		// PERFORM SBOX SUBSTITUTION
		return @($this->sbox[$byte]^$xor);}

	function sub_word($word)
	    	{   
	        for( $i=0; $i<4; $i++ ){$word[$i] = $this->sbox[$word[$i]];}
	        return $word;
	    	}

	function key_expansion($key)
	    	{
		// COMPUTE ALL ROUND KEYS
		    	
	        $key_schedule=array();		
		$key=array_values(unpack("C*",pack("H*",$key)));		
	        for($i=0;  $i < $this->Nk; $i++)
			{$key_schedule[$i] = array(($key[4*$i]),($key[4*$i+1]),($key[4*$i+2]),($key[4*$i+3]));}	
	        $i = $this->Nk;	
		
		// RCON IS CALCULATED ON THE FLY
			
		$rcon=0x8d;		
	        while ($i < $this->Nb * ($this->Nr+1) )
			{
		            $word = $key_schedule[$i-1];			    	    
		            if ($i % $this->Nk == 0)
				    {  
				        array_push($word,@array_shift($word));	// ROT WORD						      
			                $word = $this->sub_word($word);	// SBOX SUBSTITUTION
					$word[0]^=($rcon=$this->multiply($rcon));// XOR WITH RCON					
			            }
			    elseif ($this->Nk > 6 && $i % $this->Nk == 4)				    			    	
			                $word = $this->sub_word($word);	
			    
			    // XORING REMAINING WORDS WITH PREVIOUS
		            for($j=0; $j<4; $j++) {$word[$j]^= $key_schedule[$i-$this->Nk][$j];}	
		            $key_schedule[$i] = $word;
		            $i++;
	        	}
		    // REGROUP WORDS TO RETURN KEYS	    
		    $key_expansion=Array();		    
		    for ($k=0;$k<sizeof($key_schedule)-1;$k+=$this->Nb)
		    	{
			    $v2=array();			    
			    for ($j1=$k;$j1<$this->Nb+$k;$j1++)
			    	{for ($j2=0;$j2<4;$j2++) {$v2[]=$key_schedule[$j1][$j2];}}				
			    $key_expansion[]=$v2;	
			}			
		$this->keys=$key_expansion;
		}			

	function multiply($a)
		{
		$hi_bit_set = $a & 0x80;
		$a <<= 1;
		if($hi_bit_set == 0x80) $a ^= 0x1b;
		return $a % 256;	
		}
		    
	function block_encrypt($block,$xor="")
		{
		$keys = $this->keys;
		
		// COLUMN MULTIPLIERS FOR MIXING GALOIS
		
		$mul = array(2,3,1,1);
		
		$state=$block;
		
		// XOR IV IF PRESENT OR IV=LAST ENCRYPTED BLOCK
							
		if ($xor) {$temp=array();for ($g=0;$g<$this->Nb*4;$g++) {$temp[]=$state[$g] ^ $xor[$g];}$state=$temp;}

		/**
		https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
		
		Table 1: Number of rounds (Nr) as a function of the block and key length.
		
				   Nb = 4 Nb = 6 Nb = 8
				Nk = 4  10     12    14
				Nk = 6  12     12    14
				Nk = 8  14     14    14			
		*/
							
		FOR ($ROUND=1;$ROUND<$this->Nr;$ROUND++)
			{
			// SBOX SUBSTITUTION & ROWS SHIFTING & XOR WITH ROUND KEY
				
			/**
			Table 2: Shift offsets for different block lengths.
			
					4 1 2 3
					6 1 2 3
					8 1 3 4	
					
			I HAVE IMPLEMENTED THIS THROUGH C VARIABLE. BY DEFAULT SHIFTING IS STANDARD 0,1,2,3				
			*/
							
			$temp0=array();								
			for ($g=0;$g<$this->Nb;$g++)
				{						
				for ($k1=0;$k1<4;$k1++)
					{						
					$c = $k1>$this->c ? 1 : 0;$index=($g-$c+$k1*($this->Nb-1))%$this->Nb;
					$temp0[$k1][$index]=$this->sub_byte($keys[$ROUND-1][$g*4+$k1]^$state[$g*4+$k1]);
					}
				}
			// MIX COLUMNS WITH GALOIS MULTIPLICATION				
			$temp1=array();				
			for ($k1=0;$k1<4;$k1++)
				{
				for ($k3=0;$k3<$this->Nb;$k3++)
					{								
					$t="";		
					for ($k2=0;$k2<4;$k2++){$t^=$this->galois_multiplication($temp0[$k2][$k3],$mul[($k2+$k1*3)%4]);}					
					$temp1[$k3*4+$k1]=$t;
					}
				}
			// TEMP1 IS THE MIX-STATE MATRIX
			$state=$temp1;
			}
		// FINAL ROUND NO MIXING. FIRST XORING AND SUBSBOX, SECOND ROUNDKEY				
		for ($g=0;$g<$this->Nb;$g++)
			{			
			for ($k1=0;$k1<4;$k1++)
				{
				$c = $k1>$this->c ? 1 : 0;$index=($g-$c+$k1*($this->Nb-1))%$this->Nb;					
				$k0[$k1][$index]=$this->sub_byte($keys[$ROUND-1][$k1+$g*4]^$state[$k1+$g*4]);
				}
			}
			
		return $this->xor_block_key($k0,$keys[$ROUND]);		
		}
	
	function xor_block_key($block,$key)
		{
		$xor="";						
		for ($k2=0;$k2<$this->Nb;$k2++)
			{for ($k1=0;$k1<4;$k1++){$xor.=sprintf("%02x",$block[$k1][$k2]^$key[$k2*4+$k1]);}}
		return $xor;		
		}
				
	function block_decrypt($todecrypt,$i,$ecb)
		{
		// SAME SBOX, NO INVERSE TABLE
		
		// COLUMN MULTIPLIERS FOR INVERSE MIXING
		
		$mul=array(14,11,13,9);				
		$keys=$this->keys;					
		$state=array_values(unpack("C*",pack("H*",$todecrypt[$i])));
		
		// ROUNDKEY & UNSUBS-SBOX & UNXORING WITH NEXT KEY
			
		$temp=array();			
		for ($k1=0;$k1<$this->Nb*4;$k1++)
			{										
			$c = ($k1%4)>$this->c ? 1 : 0;				
			$index=($k1+4*($k1%4+$c))%$this->block_size;				
			$temp[$index]=array_Search($keys[$this->Nr][$k1]^$state[$k1],$this->sbox)^$keys[$this->Nr-1][$index];
			}			
		$state=$temp;			
		FOR ($ROUND=$this->Nr-2;$ROUND>=0;$ROUND--)
			{
			// UNMIX COLUMNS & UNSHIFT & UNSBOX & UNXORING WITH KEY				
			$ky=$keys[$ROUND];					
			for ($k1=0;$k1<4;$k1++)
				{
				$c = $k1>$this->c ? 1 : 0;					
				for ($k3=0;$k3<$this->Nb;$k3++)
					{								
					$galoism="";
					$index=($k1+($k3+$c+$k1)*4)%$this->block_size;
					for ($k2=0;$k2<4;$k2++)
						{$galoism^=$this->galois_multiplication($state[$k2+$k3*4],$mul[($k2+$k1*3)%4]) % 256;}	
					$temp[$index]=array_Search($galoism,$this->sbox)^$ky[$index];				
					}					
				}
			$state=$temp;														
			}
		// FINAL BLOCK DECRYPTING 																		
		if ($i>0)          	$ky=array_values(unpack("C*",pack("H*",$todecrypt[$i-1])));	// UNXOR WITH PREVIOUS BLOCK				  	
		else if ($this->iv)  	$ky=array_values(unpack("C*",pack("H*",$this->iv)));		// UNXOR WITH IV				
		else               	$ky=str_split(str_repeat("0",$this->Nb*4));	
								
		$decrypted_block="";
					
		for ($k1=0;$k1<$this->Nb*4;$k1++)
			{
			if (!$ecb)
				$decrypted_block.=sprintf("%02x",$state[$k1]^$ky[$k1]);
			else 	$decrypted_block.=sprintf("%02x",$state[$k1]);
			}
																					
		return $decrypted_block;
		}

	function encrypt_ecb($tocrypt)		
		{								
		$this->iv="";			    
		return $this->encrypt_cbc($tocrypt,1);
		}		    
				
	function decrypt_ecb($todecrypt)
		{
		$this->iv="";			    
		return $this->decrypt_cbc($todecrypt,1);		    
		}
		
	function encrypt_cbc($tocrypt,$ecb=0)
		{
		// no pad if mode gcm
		if (!$this->gcm_tag_length)
		$tocrypt=$this->pad($tocrypt);							
		$tocrypt=bin2hex($tocrypt);	
		
		$iv = array_values(unpack("C*",pack("H*",$this->iv)));	
		
						
		$ENCRYPTED = "";		
		$it=$this->block_size*2;		
		$tocrypt=str_Split($tocrypt,$it);					
		for ($i = 0; $i < sizeof($tocrypt); $i++)
			{					
			$enc=$this->block_encrypt(array_values(unpack("C*",pack("H*",$tocrypt[$i]))),$iv);	
			$ENCRYPTED.=$enc;
			if (!$ecb)			
			$iv=array_values(unpack("C*",pack("H*",$enc)));
			}			
		return $ENCRYPTED;
		}

	function decrypt_cbc($todecrypt,$ecb=0)
		{		
		$DECRYPTED=array();	
		$it=$this->block_size*2;
		$todecrypt=str_Split($todecrypt,$it);						
		for ($i = sizeof($todecrypt)-1; $i >=0 ; $i--)
			{					
			$dec=$this->block_decrypt($todecrypt,$i,$ecb);	
			$DECRYPTED[]=$dec;			
			}			
		return $this->unpad(pack("H*",implode(array_reverse($DECRYPTED))));
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
	
	Also, the ECB is computed internally	
	*/
			
	function encrypt_gcm($P = null, $A = null, $T = null, $tag_length = 128)
	    	{
		/**
		Same for decrypting with the T value
		*/
		
		$this->gcm_tag_length=$tag_length;
		
		if (ctype_xdigit($P)) $P=pack("H*",$P);
		if (ctype_xdigit($A)) $A=pack("H*",$A);
		
		$K=$this->K;$T1=$C2="";		
		$key_length=mb_strlen($K, '8bit') * 8;
					
		if (!in_Array($tag_length, [128, 120, 112, 104, 96])) print_r('Invalid tag length. Supported values are: 128, 120, 112, 104 and 96.');	
		
		/**		
		To check, but it works with 160 & 224 too		
		if (!in_Array($key_length, [128, 192, 256])) print_r('Bad key encryption key length. Supported values are: 128, 192 and 256.');	
		*/
				
	        list($J0, $v, $a_len_padding, $H) = $this->GCMSETUP($K, $key_length, $this->iv, $A);						
	        $C = $C3 = $this->GCTR($K, $key_length, $this->Inc(32, $J0), $P);
		
		if ($T!=null) {$C=$C2=$P;$T1=$T=pack("H*",$T);}
		
	        $u = $this->calcVector($C);		
	        $c_len_padding = $this->addPadding($C);	
	        $S = $this->Hash($H, $A.str_pad('', $v / 8, "\0").$C.str_pad('', $u / 8, "\0").$a_len_padding.$c_len_padding);
		
		if ($T==null) $C=bin2hex($C); else $C=bin2hex($C2);
		
	        $T = $this->SB($tag_length, $this->GCTR($K, $key_length, $J0, $S));
		
		if ($T1!=$T and $C2) print_r('Unable to decrypt or to verify the tag.');		
		
		$this->init("gcm",bin2hex($this->K),$this->iv_gcm);
		
		if ($C2) $C = $C3;
		
	        return [$C, bin2hex($T)];
	    	}
			        
	function GCMSETUP($K, $key_length, $IV, $A)
		{	
		$this->init('ecb',bin2hex($K),bin2hex($IV),$this->block_size); 	
		$H=pack("H*",$this->encrypt_ecb(str_repeat("\0", $this->block_size)));
		
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
		if $s!=null
			bit string consisting of the s LEFT-most bits of the bit string X
		else
			bit string consisting of the s RIGHT-most bits of the bit string X		
		*/
		
		if ($s!=null) $s=$s/8; else $init=$init/8;			
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

	function GMUL($X, $Y)
	    	{
		$Y=array_values(unpack("C*",$Y));		
		$X=array_values(unpack("C*",$X));
		
		$Ztemp=$this->galois_multiplication($X,$Y);
		
		$Z="";
		foreach ($Ztemp as $z) $Z.=sprintf("%02x",$z);
		
	        return pack("H*",$Z);
	    	}
    
	function galois_multiplication($Y,$X) 
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
		*/
		
		if (!is_array($X)) $X=array($X);
		if (!is_array($Y)) $Y=array($Y);
		
		$V=$Y;
		
		$s=sizeof($X);		
		
		if ($s==16) $R=0xe1;
		else        $R=0x1b; // same as RCON
		
		$p=str_split(str_repeat("0",$s)); 
		
		for($i = 0; $i <$s; $i++) 
			{
			if ($s==1) $f=$X[$i]; else
			$f=bindec(strrev(sprintf("%08b",$X[$i]))); // to use with little endian						
			
			for ($m=0;$m<8;$m++)
				{	 
				if ($f & 1)	for($j=0;$j<$s;$j++) $p[$j]^=$V[$j] ; 

				if ($s==1)						
					$V[0]=$this->multiply($V[0]);									
				else
					{				
					$LSB=$V[$s-1];
					
					$V[$s-1]>>=1;	
							
				        for($j=1;$j<$s;$j++)
				            {			
				            if ($V[$s-1-$j] & 1)
					    	$V[$s-$j] |= 0x80;
						    				
				            $V[$s-1-$j]>>=1;          
				            }
					    
					if ($LSB & 1)	
							$V[0]^=$R;
					}
				
			        $f>>=1;
			        }
			}
		
		if ($s==1) $p=implode($p) % 256;
		return $p;
		}
			    	           				
	function GCTR($K, $key_length, $ICB, $X)
	    	{
		/**
		output of the GCTR function for a given block cipher with key K
		applied to the bit string X with an initial counter block ICB		
		*/
		
		if (empty($X)) return '';
	        $n = (int) ceil(strlen(bin2hex($X))/32);			
	        $Y = "";
	        $CB = $ICB;
	        for ($i = 0; $i < $n; $i++)
			{		
			$C = pack("H*",$this->encrypt_ecb($CB));
			$Y.= $this->SB(128, $X, $i * 16) ^ $C;	            	
			$CB = $this->Inc(32, $CB);
			}	        	
	        $Xn = $this->SB(null, $X, $n * 128);
		$C = pack("H*",$this->encrypt_ecb($CB));
	        $Y.= $Xn ^ $this->SB($this->gLength($Xn), $C);		
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
	        $Y = str_pad('', 16, "\0");
	        $nblocks = (int) (mb_strlen($X, '8bit') / 16);
	        for ($i = 0; $i < $nblocks; $i++) 
	            $Y = $this->GMUL($Y ^ $this->SB(128, $X, $i * 16), $H);
		    	        	
	        return $Y;
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
  		
		$nonce = $this->iv_gcm;
		$key   = $this->key;
						
		list ($message_authentication_key,$message_encryption_key) = $this->derive_keys($key,$nonce);

		if (ctype_xdigit($P)) $P = pack("H*",$P);
		if (ctype_xdigit($A)) $A = pack("H*",$A);
				
		$P0 = $P;
				
		list ($blength,$A) = $this->siv_pad($A);		
		list ($bl,$P) 	   = $this->siv_pad($P);
					
		$input = bin2hex($A.$P).$blength.$bl;				
		$X   = pack("H*",$message_authentication_key.$input);	
  		$Y   = $this->siv_xor_nonce($this->siv_polyval($X));						
		$tag = $this->siv_tag($Y,$message_encryption_key);
	
		$counter_block = $this->siv_init_counter($tag); 		
		$cipher = "";
		$blocks = str_split($P0,16);
		
	        for ($i = 0; $i < sizeof($blocks); $i++) 
		    {		    
		    $cipher.=pack("H*",$this->encrypt_ecb($counter_block))^$blocks[$i];
		    $counter_block = $this->siv_inc($counter_block);  
		    }
		
		$this->init("gcm",$key,$nonce,16);
		
	        return bin2hex($cipher).$tag;
	    	} 		    

	function AES_GCM_SIV_decrypt($C,$A)
	    	{  
		$nonce=$this->iv_gcm;
		$key  =$this->key;
		  						
		list ($message_authentication_key,$message_encryption_key) = $this->derive_keys($key,$nonce);
				
		if (ctype_xdigit($C))  $C = pack("H*",$C);
		if (ctype_xdigit($A))  $A = pack("H*",$A);
		
		$tag = bin2hex(substr($C,-16));						
		$C   = str_split(substr($C,0,-16),16);
						
		$counter_block = $this->siv_init_counter($tag);										
		$this->init('ecb', $message_encryption_key,"",16);
		$plaintext = "";
				
	        for ($i = 0; $i < sizeof($C); $i++) 
		    {	    
		    $plaintext.=pack("H*",$this->encrypt_ecb($counter_block))^$C[$i];		    
		    $counter_block = $this->siv_inc($counter_block);  
		    }
		 
		// now checking auth
		 
		list ($blength,$A) = $this->siv_pad($A);		
		list ($bl,$C) 	   = $this->siv_pad($plaintext);
					
		$input = bin2hex($A.$C).$blength.$bl;		
		$X     = pack("H*",$message_authentication_key.$input);			
		$this->iv_gcm = $nonce;										
		$S_s   = $this->siv_xor_nonce($this->siv_polyval($X));						
		$expected_tag = substr($this->encrypt_ecb($S_s),0,32);
		
		$this->init("gcm",$key,$nonce,16);
		
		if ($expected_tag!=$tag) 
		    die("fail");
		  		
		return bin2hex($plaintext);
	    	}
		    
	function derive_keys($key, $nonce) 
		{		  		  
		  $this->init('ecb',$key,$nonce,16);		  
		  
		  $keys="";for ($k=0;$k<6;$k++) $keys.="0$k"."000000".$nonce;					  
		  $kenc=$this->encrypt_ecb(pack("H*",$keys));

		  $message_authentication_key 	= substr($kenc,0,16).substr($kenc,32,16);
		  $message_encryption_key 	= substr($kenc,64,16).substr($kenc,96,16);	
						
		  if (strlen($key) == 64) 			  	    			  
		        $message_encryption_key.= substr($kenc,128,16).substr($kenc,160,16);
			  			  
		  return [$message_authentication_key, $message_encryption_key];
		}

	function siv_pad($m)
		{
		$len=strlen($m)*8;		
		$len=sprintf("%02x%02x",$len & 255, ($len/256) & 255);
		$blength=$len.str_Repeat("0",16-strlen($len));		
		$pad=0;$mod=strlen($m)%16;
						
		if ($mod!=0)	$pad=16-$mod;						
		if ($m!="")	$m.=str_repeat("\x0",$pad);
			
		return [$blength,$m];		
		}
		
	function siv_polyval($X)
		{
		$Y = str_pad('', 16, "\0");		
		$H  = pack("H*","40000000000000000000000000000000");		
		$X=str_split(strrev($X) , 16);		
	        $nblocks = sizeof($X) - 1;		
		$H = $this->GMUL($Y ^ $X[$nblocks],$H);
		
	        for ($i = $nblocks-1; $i >= 0; $i--) 
			$Y = $this->GMUL($Y ^ $X[$i] , $H);		    
		    	
  		return strrev($Y);		
		}
		
	function siv_tag($Y,$message_encryption_key)
		{
		$this->init('ecb', $message_encryption_key,"",16);		
		return substr($this->encrypt_ecb($Y),0,32);		
		}
		
	function siv_xor_nonce($Y)
		{
		$Y=str_split($Y);		
		$nonce=str_split(pack("H*",$this->iv_gcm));		

		for ($i = 0; $i < 12; $i++) 	
			$Y[$i]^= $nonce[$i];			   
		  
		$Y[15]=pack("H*",sprintf("%02x",ord($Y[15]) & 0x7f));	
		
		return implode($Y); 		
		}
		
	function siv_init_counter($tag)
		{
		$counter_block = str_split(pack("H*",$tag));	
		$counter_block[15]|="\x80";		
		return implode($counter_block); 		
		}
		
	function siv_inc($counter)
		{
	        for ($j = 16; $j >= 4; $j-=4) 
			{
		        $temp = strrev(substr($counter, -$j, 4));
	                extract(unpack('Ncount', $temp));		
	                $long=pack('N', $count+1);
			$counter = substr_replace($counter, strrev($long), -$j, 4);			
			if ($temp!=0xFFFFFFFF and $temp!=0x7FFFFFFF) break;					
		        }
		return $counter;		
		}
					
	function encrypt($tocrypt,$A="",$T=null,$taglength=128)
		{
		return $this->encrypt_gcm($tocrypt,$A,$T,$taglength);
		}

	function decrypt($todecrypt,$A="",$T=null,$taglength=128)
		{
		return $this->encrypt_gcm($todecrypt,$A,$T,$taglength);
		}
										
	function pad($text='')
		{
		$length = strlen($text);
		$padding =  $this->block_size - ($length  % $this->block_size );
		$text = str_pad($text,  $length + $padding, chr($padding) );
		return $text;
		}
		
     	function unpad($text='')
		{			
		$padded = (int) ord($text[strlen($text)-1]);
		$padded = ($padded > $this->block_size ? $this->block_size : $padded);
		$text = substr($text,0,strlen($text)-$padded);
		return rtrim($text, "\0"); // TO AVOID BAD MCRYPT PADDING		
		}		 
	}

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

ECHO "AES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf \n\n";

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
		
	$x->init("gcm",$K,$IV,16);
	
	list($C, $T) = $x->encrypt($P, $A, "",128);
	
	echo "COMPUTED C $C\nCOMPUTED T $T\n\n";
	
	list($P, $T) = $x->decrypt($C, $A, $T,128);

	echo "DECRYPTED P ".bin2hex($P)."\nDECRYPTED T $T\n\n";	
	}
}

//testvectors_gcm();

function check_AES_GCM_SIV()
	{	
	// https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html#rfc.status Appendix C. Test vectors
	
	
	ECHO "AES GCM SIV test vectors from https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html \n\n";

	$test_vectors='	

Plaintext (0 bytes) =
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             00000000000000000000000000000000
POLYVAL result =            00000000000000000000000000000000
POLYVAL result XOR nonce =  03000000000000000000000000000000
... and masked =            03000000000000000000000000000000
Tag =                       dc20e2d83f25705bb49e439eca56de25
Initial counter =           dc20e2d83f25705bb49e439eca56dea5
Result (16 bytes) =         dc20e2d83f25705bb49e439eca56de25



Plaintext (8 bytes) =       0100000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            00000000000000004000000000000000
POLYVAL result =            eb93b7740962c5e49d2a90a7dc5cec74
POLYVAL result XOR nonce =  e893b7740962c5e49d2a90a7dc5cec74
... and masked =            e893b7740962c5e49d2a90a7dc5cec74
Tag =                       578782fff6013b815b287c22493a364c
Initial counter =           578782fff6013b815b287c22493a36cc
Result (24 bytes) =         b5d839330ac7b786578782fff6013b81
                            5b287c22493a364c


Plaintext (12 bytes) =      010000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            00000000000000006000000000000000
POLYVAL result =            48eb6c6c5a2dbe4a1dde508fee06361b
POLYVAL result XOR nonce =  4beb6c6c5a2dbe4a1dde508fee06361b
... and masked =            4beb6c6c5a2dbe4a1dde508fee06361b
Tag =                       a4978db357391a0bc4fdec8b0d106639
Initial counter =           a4978db357391a0bc4fdec8b0d1066b9
Result (28 bytes) =         7323ea61d05932260047d942a4978db3
                            57391a0bc4fdec8b0d106639


Plaintext (16 bytes) =      01000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            00000000000000008000000000000000
POLYVAL result =            20806c26e3c1de019e111255708031d6
POLYVAL result XOR nonce =  23806c26e3c1de019e111255708031d6
... and masked =            23806c26e3c1de019e11125570803156
Tag =                       303aaf90f6fe21199c6068577437a0c4
Initial counter =           303aaf90f6fe21199c6068577437a0c4
Result (32 bytes) =         743f7c8077ab25f8624e2e948579cf77
                            303aaf90f6fe21199c6068577437a0c4


Plaintext (32 bytes) =      01000000000000000000000000000000
                            02000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            00000000000000000001000000000000
POLYVAL result =            ce6edc9a50b36d9a98986bbf6a261c3b
POLYVAL result XOR nonce =  cd6edc9a50b36d9a98986bbf6a261c3b
... and masked =            cd6edc9a50b36d9a98986bbf6a261c3b
Tag =                       1a8e45dcd4578c667cd86847bf6155ff
Initial counter =           1a8e45dcd4578c667cd86847bf6155ff
Result (48 bytes) =         84e07e62ba83a6585417245d7ec413a9
                            fe427d6315c09b57ce45f2e3936a9445
                            1a8e45dcd4578c667cd86847bf6155ff


Plaintext (48 bytes) =      01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            00000000000000008001000000000000
POLYVAL result =            81388746bc22d26b2abc3dcb15754222
POLYVAL result XOR nonce =  82388746bc22d26b2abc3dcb15754222
... and masked =            82388746bc22d26b2abc3dcb15754222
Tag =                       5e6e311dbf395d35b0fe39c2714388f8
Initial counter =           5e6e311dbf395d35b0fe39c2714388f8
Result (64 bytes) =         3fd24ce1f5a67b75bf2351f181a475c7
                            b800a5b4d3dcf70106b1eea82fa1d64d
                            f42bf7226122fa92e17a40eeaac1201b
                            5e6e311dbf395d35b0fe39c2714388f8


Plaintext (64 bytes) =      01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            00000000000000000002000000000000
POLYVAL result =            1e39b6d3344d348f6044f89935d1cf78
POLYVAL result XOR nonce =  1d39b6d3344d348f6044f89935d1cf78
... and masked =            1d39b6d3344d348f6044f89935d1cf78
Tag =                       8a263dd317aa88d56bdf3936dba75bb8
Initial counter =           8a263dd317aa88d56bdf3936dba75bb8
Result (80 bytes) =         2433668f1058190f6d43e360f4f35cd8
                            e475127cfca7028ea8ab5c20f7ab2af0
                            2516a2bdcbc08d521be37ff28c152bba
                            36697f25b4cd169c6590d1dd39566d3f
                            8a263dd317aa88d56bdf3936dba75bb8


Plaintext (8 bytes) =       0200000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            08000000000000004000000000000000
POLYVAL result =            b26781e7e2c1376f96bec195f3709b2a
POLYVAL result XOR nonce =  b16781e7e2c1376f96bec195f3709b2a
... and masked =            b16781e7e2c1376f96bec195f3709b2a
Tag =                       3b0a1a2560969cdf790d99759abd1508
Initial counter =           3b0a1a2560969cdf790d99759abd1588
Result (24 bytes) =         1e6daba35669f4273b0a1a2560969cdf
                            790d99759abd1508


Plaintext (12 bytes) =      020000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            08000000000000006000000000000000
POLYVAL result =            111f5affb18e4cc1164a01bdc12a4145
POLYVAL result XOR nonce =  121f5affb18e4cc1164a01bdc12a4145
... and masked =            121f5affb18e4cc1164a01bdc12a4145
Tag =                       08299c5102745aaa3a0c469fad9e075a
Initial counter =           08299c5102745aaa3a0c469fad9e07da
Result (28 bytes) =         296c7889fd99f41917f4462008299c51
                            02745aaa3a0c469fad9e075a


Plaintext (16 bytes) =      02000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            08000000000000008000000000000000
POLYVAL result =            79745ab508622c8a958543675fac4688
POLYVAL result XOR nonce =  7a745ab508622c8a958543675fac4688
... and masked =            7a745ab508622c8a958543675fac4608
Tag =                       8f8936ec039e4e4bb97ebd8c4457441f
Initial counter =           8f8936ec039e4e4bb97ebd8c4457449f
Result (32 bytes) =         e2b0c5da79a901c1745f700525cb335b
                            8f8936ec039e4e4bb97ebd8c4457441f


Plaintext (32 bytes) =      02000000000000000000000000000000
                            03000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            08000000000000000001000000000000
POLYVAL result =            2ce7daaf7c89490822051255b12eca6b
POLYVAL result XOR nonce =  2fe7daaf7c89490822051255b12eca6b
... and masked =            2fe7daaf7c89490822051255b12eca6b
Tag =                       e6af6a7f87287da059a71684ed3498e1
Initial counter =           e6af6a7f87287da059a71684ed3498e1
Result (48 bytes) =         620048ef3c1e73e57e02bb8562c416a3
                            19e73e4caac8e96a1ecb2933145a1d71
                            e6af6a7f87287da059a71684ed3498e1


Plaintext (48 bytes) =      02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            08000000000000008001000000000000
POLYVAL result =            9ca987715d69c1786711dfcd22f830fc
POLYVAL result XOR nonce =  9fa987715d69c1786711dfcd22f830fc
... and masked =            9fa987715d69c1786711dfcd22f8307c
Tag =                       6a8cc3865f76897c2e4b245cf31c51f2
Initial counter =           6a8cc3865f76897c2e4b245cf31c51f2
Result (64 bytes) =         50c8303ea93925d64090d07bd109dfd9
                            515a5a33431019c17d93465999a8b005
                            3201d723120a8562b838cdff25bf9d1e
                            6a8cc3865f76897c2e4b245cf31c51f2


Plaintext (64 bytes) =      02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            05000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            05000000000000000000000000000000
                            08000000000000000002000000000000
POLYVAL result =            ffcd05d5770f34ad9267f0a59994b15a
POLYVAL result XOR nonce =  fccd05d5770f34ad9267f0a59994b15a
... and masked =            fccd05d5770f34ad9267f0a59994b15a
Tag =                       cdc46ae475563de037001ef84ae21744
Initial counter =           cdc46ae475563de037001ef84ae217c4
Result (80 bytes) =         2f5c64059db55ee0fb847ed513003746
                            aca4e61c711b5de2e7a77ffd02da42fe
                            ec601910d3467bb8b36ebbaebce5fba3
                            0d36c95f48a3e7980f0e7ac299332a80
                            cdc46ae475563de037001ef84ae21744


Plaintext (4 bytes) =       02000000
AAD (12 bytes) =            010000000000000000000000
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            60000000000000002000000000000000
POLYVAL result =            f6ce9d3dcd68a2fd603c7ecc18fb9918
POLYVAL result XOR nonce =  f5ce9d3dcd68a2fd603c7ecc18fb9918
... and masked =            f5ce9d3dcd68a2fd603c7ecc18fb9918
Tag =                       07eb1f84fb28f8cb73de8e99e2f48a14
Initial counter =           07eb1f84fb28f8cb73de8e99e2f48a94
Result (20 bytes) =         a8fe3e8707eb1f84fb28f8cb73de8e99
                            e2f48a14


Plaintext (20 bytes) =      03000000000000000000000000000000
                            04000000
AAD (18 bytes) =            01000000000000000000000000000000
                            0200
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            9000000000000000a000000000000000
POLYVAL result =            4781d492cb8f926c504caa36f61008fe
POLYVAL result XOR nonce =  4481d492cb8f926c504caa36f61008fe
... and masked =            4481d492cb8f926c504caa36f610087e
Tag =                       24afc9805e976f451e6d87f6fe106514
Initial counter =           24afc9805e976f451e6d87f6fe106594
Result (36 bytes) =         6bb0fecf5ded9b77f902c7d5da236a43
                            91dd029724afc9805e976f451e6d87f6
                            fe106514


Plaintext (18 bytes) =      03000000000000000000000000000000
                            0400
AAD (20 bytes) =            01000000000000000000000000000000
                            02000000
Key =                       01000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = d9b360279694941ac5dbc6987ada7377
Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            a0000000000000009000000000000000
POLYVAL result =            75cbc23a1a10e348aeb8e384b5cc79fd
POLYVAL result XOR nonce =  76cbc23a1a10e348aeb8e384b5cc79fd
... and masked =            76cbc23a1a10e348aeb8e384b5cc797d
Tag =                       bff9b2ef00fb47920cc72a0c0f13b9fd
Initial counter =           bff9b2ef00fb47920cc72a0c0f13b9fd
Result (34 bytes) =         44d0aaf6fb2f1f34add5e8064e83e12a
                            2adabff9b2ef00fb47920cc72a0c0f13
                            b9fd
			    		    
			    
Plaintext (0 bytes) =
AAD (0 bytes) =
Key =                       e66021d5eb8e4f4066d4adb9c33560e4
Nonce =                     f46e44bb3da0015c94f70887
Record authentication key = 036ee1fe2d7926af68898095e54e7b3c
Record encryption key =     5e46482396008223b5c1d25173d87539
POLYVAL input =             00000000000000000000000000000000
POLYVAL result =            00000000000000000000000000000000
POLYVAL result XOR nonce =  f46e44bb3da0015c94f7088700000000
... and masked =            f46e44bb3da0015c94f7088700000000
Tag =                       a4194b79071b01a87d65f706e3949578
Initial counter =           a4194b79071b01a87d65f706e39495f8
Result (16 bytes) =         a4194b79071b01a87d65f706e3949578


Plaintext (3 bytes) =       7a806c
AAD (5 bytes) =             46bb91c3c5
Key =                       36864200e0eaf5284d884a0e77d31646
Nonce =                     bae8e37fc83441b16034566b
Record authentication key = 3e28de1120b2981a0155795ca2812af6
Record encryption key =     6d4b78b31a4c9c03d8db0f42f7507fae
POLYVAL input =             46bb91c3c50000000000000000000000
                            7a806c00000000000000000000000000
                            28000000000000001800000000000000
POLYVAL result =            43d9a745511dcfa21b96dd606f1d5720
POLYVAL result XOR nonce =  f931443a99298e137ba28b0b6f1d5720
... and masked =            f931443a99298e137ba28b0b6f1d5720
Tag =                       711bd85bc1e4d3e0a462e074eea428a8
Initial counter =           711bd85bc1e4d3e0a462e074eea428a8
Result (19 bytes) =         af60eb711bd85bc1e4d3e0a462e074ee
                            a428a8


Plaintext (6 bytes) =       bdc66f146545
AAD (10 bytes) =            fc880c94a95198874296
Key =                       aedb64a6c590bc84d1a5e269e4b47801
Nonce =                     afc0577e34699b9e671fdd4f
Record authentication key = 43b8de9cea62330d15cccfc84a33e8c8
Record encryption key =     8e54631607e431e095b54852868e3a27
POLYVAL input =             fc880c94a95198874296000000000000
                            bdc66f14654500000000000000000000
                            50000000000000003000000000000000
POLYVAL result =            26498e0d2b1ef004e808c458e8f2f515
POLYVAL result XOR nonce =  8989d9731f776b9a8f171917e8f2f515
... and masked =            8989d9731f776b9a8f171917e8f2f515
Tag =                       d6a9c45545cfc11f03ad743dba20f966
Initial counter =           d6a9c45545cfc11f03ad743dba20f9e6
Result (22 bytes) =         bb93a3e34d3cd6a9c45545cfc11f03ad
                            743dba20f966


Plaintext (9 bytes) =       1177441f195495860f
AAD (15 bytes) =            046787f3ea22c127aaf195d1894728
Key =                       d5cc1fd161320b6920ce07787f86743b
Nonce =                     275d1ab32f6d1f0434d8848c
Record authentication key = 8a51df64d93eaf667c2c09bd454ce5c5
Record encryption key =     43ab276c2b4a473918ca73f2dd85109c
POLYVAL input =             046787f3ea22c127aaf195d189472800
                            1177441f195495860f00000000000000
                            78000000000000004800000000000000
POLYVAL result =            63a3451c0b23345ad02bba59956517cf
POLYVAL result XOR nonce =  44fe5faf244e2b5ee4f33ed5956517cf
... and masked =            44fe5faf244e2b5ee4f33ed59565174f
Tag =                       1d02fd0cd174c84fc5dae2f60f52fd2b
Initial counter =           1d02fd0cd174c84fc5dae2f60f52fdab
Result (25 bytes) =         4f37281f7ad12949d01d02fd0cd174c8
                            4fc5dae2f60f52fd2b


Plaintext (12 bytes) =      9f572c614b4745914474e7c7
AAD (20 bytes) =            c9882e5386fd9f92ec489c8fde2be2cf
                            97e74e93
Key =                       b3fed1473c528b8426a582995929a149
Nonce =                     9e9ad8780c8d63d0ab4149c0
Record authentication key = 22f50707a95dd416df069d670cb775e8
Record encryption key =     f674a5584ee21fe97b4cebc468ab61e4
POLYVAL input =             c9882e5386fd9f92ec489c8fde2be2cf
                            97e74e93000000000000000000000000
                            9f572c614b4745914474e7c700000000
                            a0000000000000006000000000000000
POLYVAL result =            0cca0423fba9d77fe7e2e6963b08cdd0
POLYVAL result XOR nonce =  9250dc5bf724b4af4ca3af563b08cdd0
... and masked =            9250dc5bf724b4af4ca3af563b08cd50
Tag =                       c1dc2f871fb7561da1286e655e24b7b0
Initial counter =           c1dc2f871fb7561da1286e655e24b7b0
Result (28 bytes) =         f54673c5ddf710c745641c8bc1dc2f87
                            1fb7561da1286e655e24b7b0


Plaintext (15 bytes) =      0d8c8451178082355c9e940fea2f58
AAD (25 bytes) =            2950a70d5a1db2316fd568378da107b5
                            2b0da55210cc1c1b0a
Key =                       2d4ed87da44102952ef94b02b805249b
Nonce =                     ac80e6f61455bfac8308a2d4
Record authentication key = 0b00a29a83e7e95b92e3a0783b29f140
Record encryption key =     a430c27f285aed913005975c42eed5f3
POLYVAL input =             2950a70d5a1db2316fd568378da107b5
                            2b0da55210cc1c1b0a00000000000000
                            0d8c8451178082355c9e940fea2f5800
                            c8000000000000007800000000000000
POLYVAL result =            1086ef25247aa41009bbc40871d9b350
POLYVAL result XOR nonce =  bc0609d3302f1bbc8ab366dc71d9b350
... and masked =            bc0609d3302f1bbc8ab366dc71d9b350
Tag =                       83b3449b9f39552de99dc214a1190b0b
Initial counter =           83b3449b9f39552de99dc214a1190b8b
Result (31 bytes) =         c9ff545e07b88a015f05b274540aa183
                            b3449b9f39552de99dc214a1190b0b


Plaintext (18 bytes) =      6b3db4da3d57aa94842b9803a96e07fb
                            6de7
AAD (30 bytes) =            1860f762ebfbd08284e421702de0de18
                            baa9c9596291b08466f37de21c7f
Key =                       bde3b2f204d1e9f8b06bc47f9745b3d1
Nonce =                     ae06556fb6aa7890bebc18fe
Record authentication key = 21c874a8bad3603d1c3e8784df5b3f9f
Record encryption key =     d1c16d72651c3df504eae27129d818e8
POLYVAL input =             1860f762ebfbd08284e421702de0de18
                            baa9c9596291b08466f37de21c7f0000
                            6b3db4da3d57aa94842b9803a96e07fb
                            6de70000000000000000000000000000
                            f0000000000000009000000000000000
POLYVAL result =            55462a5afa0da8d646481e049ef9c764
POLYVAL result XOR nonce =  fb407f354ca7d046f8f406fa9ef9c764
... and masked =            fb407f354ca7d046f8f406fa9ef9c764
Tag =                       3e377094f04709f64d7b985310a4db84
Initial counter =           3e377094f04709f64d7b985310a4db84
Result (34 bytes) =         6298b296e24e8cc35dce0bed484b7f30
                            d5803e377094f04709f64d7b985310a4
                            db84


Plaintext (21 bytes) =      e42a3c02c25b64869e146d7b233987bd
                            dfc240871d
AAD (35 bytes) =            7576f7028ec6eb5ea7e298342a94d4b2
                            02b370ef9768ec6561c4fe6b7e7296fa
                            859c21
Key =                       f901cfe8a69615a93fdf7a98cad48179
Nonce =                     6245709fb18853f68d833640
Record authentication key = 3724f55f1d22ac0ab830da0b6a995d74
Record encryption key =     75ac87b70c05db287de779006105a344
POLYVAL input =             7576f7028ec6eb5ea7e298342a94d4b2
                            02b370ef9768ec6561c4fe6b7e7296fa
                            859c2100000000000000000000000000
                            e42a3c02c25b64869e146d7b233987bd
                            dfc240871d0000000000000000000000
                            1801000000000000a800000000000000
POLYVAL result =            4cbba090f03f7d1188ea55749fa6c7bd
POLYVAL result XOR nonce =  2efed00f41b72ee7056963349fa6c7bd
... and masked =            2efed00f41b72ee7056963349fa6c73d
Tag =                       2d15506c84a9edd65e13e9d24a2a6e70
Initial counter =           2d15506c84a9edd65e13e9d24a2a6ef0
Result (37 bytes) =         391cc328d484a4f46406181bcd62efd9
                            b3ee197d052d15506c84a9edd65e13e9
                            d24a2a6e70
			    


Plaintext (0 bytes) =
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             00000000000000000000000000000000
POLYVAL result =            00000000000000000000000000000000
POLYVAL result XOR nonce =  03000000000000000000000000000000
... and masked =            03000000000000000000000000000000
Tag =                       07f5f4169bbf55a8400cd47ea6fd400f
Initial counter =           07f5f4169bbf55a8400cd47ea6fd408f
Result (16 bytes) =         07f5f4169bbf55a8400cd47ea6fd400f


Plaintext (8 bytes) =       0100000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            00000000000000004000000000000000
POLYVAL result =            05230f62f0eac8aa14fe4d646b59cd41
POLYVAL result XOR nonce =  06230f62f0eac8aa14fe4d646b59cd41
... and masked =            06230f62f0eac8aa14fe4d646b59cd41
Tag =                       843122130f7364b761e0b97427e3df28
Initial counter =           843122130f7364b761e0b97427e3dfa8
Result (24 bytes) =         c2ef328e5c71c83b843122130f7364b7
                            61e0b97427e3df28


Plaintext (12 bytes) =      010000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            00000000000000006000000000000000
POLYVAL result =            6d81a24732fd6d03ae5af544720a1c13
POLYVAL result XOR nonce =  6e81a24732fd6d03ae5af544720a1c13
... and masked =            6e81a24732fd6d03ae5af544720a1c13
Tag =                       8ca50da9ae6559e48fd10f6e5c9ca17e
Initial counter =           8ca50da9ae6559e48fd10f6e5c9ca1fe
Result (28 bytes) =         9aab2aeb3faa0a34aea8e2b18ca50da9
                            ae6559e48fd10f6e5c9ca17e


Plaintext (16 bytes) =      01000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            00000000000000008000000000000000
POLYVAL result =            74eee2bf7c9a165f8b25dea73db32a6d
POLYVAL result XOR nonce =  77eee2bf7c9a165f8b25dea73db32a6d
... and masked =            77eee2bf7c9a165f8b25dea73db32a6d
Tag =                       c9eac6fa700942702e90862383c6c366
Initial counter =           c9eac6fa700942702e90862383c6c3e6
Result (32 bytes) =         85a01b63025ba19b7fd3ddfc033b3e76
                            c9eac6fa700942702e90862383c6c366


Plaintext (32 bytes) =      01000000000000000000000000000000
                            02000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            00000000000000000001000000000000
POLYVAL result =            899b6381b3d46f0def7aa0517ba188f5
POLYVAL result XOR nonce =  8a9b6381b3d46f0def7aa0517ba188f5
... and masked =            8a9b6381b3d46f0def7aa0517ba18875
Tag =                       e819e63abcd020b006a976397632eb5d
Initial counter =           e819e63abcd020b006a976397632ebdd
Result (48 bytes) =         4a6a9db4c8c6549201b9edb53006cba8
                            21ec9cf850948a7c86c68ac7539d027f
                            e819e63abcd020b006a976397632eb5d


Plaintext (48 bytes) =      01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            00000000000000008001000000000000
POLYVAL result =            c1f8593d8fc29b0c290cae1992f71f51
POLYVAL result XOR nonce =  c2f8593d8fc29b0c290cae1992f71f51
... and masked =            c2f8593d8fc29b0c290cae1992f71f51
Tag =                       790bc96880a99ba804bd12c0e6a22cc4
Initial counter =           790bc96880a99ba804bd12c0e6a22cc4
Result (64 bytes) =         c00d121893a9fa603f48ccc1ca3c57ce
                            7499245ea0046db16c53c7c66fe717e3
                            9cf6c748837b61f6ee3adcee17534ed5
                            790bc96880a99ba804bd12c0e6a22cc4


Plaintext (64 bytes) =      01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
AAD (0 bytes) =
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            00000000000000000002000000000000
POLYVAL result =            6ef38b06046c7c0e225efaef8e2ec4c4
POLYVAL result XOR nonce =  6df38b06046c7c0e225efaef8e2ec4c4
... and masked =            6df38b06046c7c0e225efaef8e2ec444
Tag =                       112864c269fc0d9d88c61fa47e39aa08
Initial counter =           112864c269fc0d9d88c61fa47e39aa88
Result (80 bytes) =         c2d5160a1f8683834910acdafc41fbb1
                            632d4a353e8b905ec9a5499ac34f96c7
                            e1049eb080883891a4db8caaa1f99dd0
                            04d80487540735234e3744512c6f90ce
                            112864c269fc0d9d88c61fa47e39aa08


Plaintext (8 bytes) =       0200000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            08000000000000004000000000000000
POLYVAL result =            34e57bafe011b9b36fc6821b7ffb3354
POLYVAL result XOR nonce =  37e57bafe011b9b36fc6821b7ffb3354
... and masked =            37e57bafe011b9b36fc6821b7ffb3354
Tag =                       91213f267e3b452f02d01ae33e4ec854
Initial counter =           91213f267e3b452f02d01ae33e4ec8d4
Result (24 bytes) =         1de22967237a813291213f267e3b452f
                            02d01ae33e4ec854


Plaintext (12 bytes) =      020000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            08000000000000006000000000000000
POLYVAL result =            5c47d68a22061c1ad5623a3b66a8e206
POLYVAL result XOR nonce =  5f47d68a22061c1ad5623a3b66a8e206
... and masked =            5f47d68a22061c1ad5623a3b66a8e206
Tag =                       c1a4a19ae800941ccdc57cc8413c277f
Initial counter =           c1a4a19ae800941ccdc57cc8413c27ff
Result (28 bytes) =         163d6f9cc1b346cd453a2e4cc1a4a19a
                            e800941ccdc57cc8413c277f


Plaintext (16 bytes) =      02000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            08000000000000008000000000000000
POLYVAL result =            452896726c616746f01d11d82911d478
POLYVAL result XOR nonce =  462896726c616746f01d11d82911d478
... and masked =            462896726c616746f01d11d82911d478
Tag =                       b292d28ff61189e8e49f3875ef91aff7
Initial counter =           b292d28ff61189e8e49f3875ef91aff7
Result (32 bytes) =         c91545823cc24f17dbb0e9e807d5ec17
                            b292d28ff61189e8e49f3875ef91aff7


Plaintext (32 bytes) =      02000000000000000000000000000000
                            03000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            08000000000000000001000000000000
POLYVAL result =            4e58c1e341c9bb0ae34eda9509dfc90c
POLYVAL result XOR nonce =  4d58c1e341c9bb0ae34eda9509dfc90c
... and masked =            4d58c1e341c9bb0ae34eda9509dfc90c
Tag =                       aea1bad12702e1965604374aab96dbbc
Initial counter =           aea1bad12702e1965604374aab96dbbc
Result (48 bytes) =         07dad364bfc2b9da89116d7bef6daaaf
                            6f255510aa654f920ac81b94e8bad365
                            aea1bad12702e1965604374aab96dbbc


Plaintext (48 bytes) =      02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            08000000000000008001000000000000
POLYVAL result =            2566a4aff9a525df9772c16d4eaf8d2a
POLYVAL result XOR nonce =  2666a4aff9a525df9772c16d4eaf8d2a
... and masked =            2666a4aff9a525df9772c16d4eaf8d2a
Tag =                       03332742b228c647173616cfd44c54eb
Initial counter =           03332742b228c647173616cfd44c54eb
Result (64 bytes) =         c67a1f0f567a5198aa1fcc8e3f213143
                            36f7f51ca8b1af61feac35a86416fa47
                            fbca3b5f749cdf564527f2314f42fe25
                            03332742b228c647173616cfd44c54eb


Plaintext (64 bytes) =      02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            05000000000000000000000000000000
AAD (1 bytes) =             01
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            05000000000000000000000000000000
                            08000000000000000002000000000000
POLYVAL result =            da58d2f61b0a9d343b2f37fb0c519733
POLYVAL result XOR nonce =  d958d2f61b0a9d343b2f37fb0c519733
... and masked =            d958d2f61b0a9d343b2f37fb0c519733
Tag =                       5bde0285037c5de81e5b570a049b62a0
Initial counter =           5bde0285037c5de81e5b570a049b62a0
Result (80 bytes) =         67fd45e126bfb9a79930c43aad2d3696
                            7d3f0e4d217c1e551f59727870beefc9
                            8cb933a8fce9de887b1e40799988db1f
                            c3f91880ed405b2dd298318858467c89
                            5bde0285037c5de81e5b570a049b62a0


Plaintext (4 bytes) =       02000000
AAD (12 bytes) =            010000000000000000000000
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            60000000000000002000000000000000
POLYVAL result =            6dc76ae84b88916e073a303aafde05cf
POLYVAL result XOR nonce =  6ec76ae84b88916e073a303aafde05cf
... and masked =            6ec76ae84b88916e073a303aafde054f
Tag =                       1835e517741dfddccfa07fa4661b74cf
Initial counter =           1835e517741dfddccfa07fa4661b74cf
Result (20 bytes) =         22b3f4cd1835e517741dfddccfa07fa4
                            661b74cf


Plaintext (20 bytes) =      03000000000000000000000000000000
                            04000000
AAD (18 bytes) =            01000000000000000000000000000000
                            0200
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            9000000000000000a000000000000000
POLYVAL result =            973ef4fd04bd31d193816ab26f8655ca
POLYVAL result XOR nonce =  943ef4fd04bd31d193816ab26f8655ca
... and masked =            943ef4fd04bd31d193816ab26f86554a
Tag =                       b879ad976d8242acc188ab59cabfe307
Initial counter =           b879ad976d8242acc188ab59cabfe387
Result (36 bytes) =         43dd0163cdb48f9fe3212bf61b201976
                            067f342bb879ad976d8242acc188ab59
                            cabfe307


Plaintext (18 bytes) =      03000000000000000000000000000000
                            0400
AAD (20 bytes) =            01000000000000000000000000000000
                            02000000
Key =                       01000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     030000000000000000000000
Record authentication key = b5d3c529dfafac43136d2d11be284d7f
Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
                            456e3c6c05ecc157cdbf0700fedad222
POLYVAL input =             01000000000000000000000000000000
                            02000000000000000000000000000000
                            03000000000000000000000000000000
                            04000000000000000000000000000000
                            a0000000000000009000000000000000
POLYVAL result =            2cbb6b7ab2dbffefb797f825f826870c
POLYVAL result XOR nonce =  2fbb6b7ab2dbffefb797f825f826870c
... and masked =            2fbb6b7ab2dbffefb797f825f826870c
Tag =                       cfcdf5042112aa29685c912fc2056543
Initial counter =           cfcdf5042112aa29685c912fc20565c3
Result (34 bytes) =         462401724b5ce6588d5a54aae5375513
                            a075cfcdf5042112aa29685c912fc205
                            6543

Plaintext (0 bytes) =
AAD (0 bytes) =
Key =                       e66021d5eb8e4f4066d4adb9c33560e4
                            f46e44bb3da0015c94f7088736864200
Nonce =                     e0eaf5284d884a0e77d31646
Record authentication key = e40d26f82774aa27f47b047b608b9585
Record encryption key =     7c7c3d9a542cef53dde0e6de9b580040
                            0f82e73ec5f7ee41b7ba8dcb9ba078c3
POLYVAL input =             00000000000000000000000000000000
POLYVAL result =            00000000000000000000000000000000
POLYVAL result XOR nonce =  e0eaf5284d884a0e77d3164600000000
... and masked =            e0eaf5284d884a0e77d3164600000000
Tag =                       169fbb2fbf389a995f6390af22228a62
Initial counter =           169fbb2fbf389a995f6390af22228ae2
Result (16 bytes) =         169fbb2fbf389a995f6390af22228a62


Plaintext (3 bytes) =       671fdd
AAD (5 bytes) =             4fbdc66f14
Key =                       bae8e37fc83441b16034566b7a806c46
                            bb91c3c5aedb64a6c590bc84d1a5e269
Nonce =                     e4b47801afc0577e34699b9e
Record authentication key = b546f5a850d0a90adfe39e95c2510fc6
Record encryption key =     b9d1e239d62cbb5c49273ddac8838bdc
                            c53bca478a770f07087caa4e0a924a55
POLYVAL input =             4fbdc66f140000000000000000000000
                            671fdd00000000000000000000000000
                            28000000000000001800000000000000
POLYVAL result =            b91f91f96b159a7c611c05035b839e92
POLYVAL result XOR nonce =  5dabe9f8c4d5cd0255759e9d5b839e92
... and masked =            5dabe9f8c4d5cd0255759e9d5b839e12
Tag =                       93da9bb81333aee0c785b240d319719d
Initial counter =           93da9bb81333aee0c785b240d319719d
Result (19 bytes) =         0eaccb93da9bb81333aee0c785b240d3
                            19719d


Plaintext (6 bytes) =       195495860f04
AAD (10 bytes) =            6787f3ea22c127aaf195
Key =                       6545fc880c94a95198874296d5cc1fd1
                            61320b6920ce07787f86743b275d1ab3
Nonce =                     2f6d1f0434d8848c1177441f
Record authentication key = e156e1f9b0b07b780cbe30f259e3c8da
Record encryption key =     6fc1c494519f944aae52fcd8b14e5b17
                            1b5a9429d3b76e430d49940c0021d612
POLYVAL input =             6787f3ea22c127aaf195000000000000
                            195495860f0400000000000000000000
                            50000000000000003000000000000000
POLYVAL result =            2c480ed9d236b1df24c6eec109bd40c1
POLYVAL result XOR nonce =  032511dde6ee355335b1aade09bd40c1
... and masked =            032511dde6ee355335b1aade09bd4041
Tag =                       6b62b84dc40c84636a5ec12020ec8c2c
Initial counter =           6b62b84dc40c84636a5ec12020ec8cac
Result (22 bytes) =         a254dad4f3f96b62b84dc40c84636a5e
                            c12020ec8c2c


Plaintext (9 bytes) =       c9882e5386fd9f92ec
AAD (15 bytes) =            489c8fde2be2cf97e74e932d4ed87d
Key =                       d1894728b3fed1473c528b8426a58299
                            5929a1499e9ad8780c8d63d0ab4149c0
Nonce =                     9f572c614b4745914474e7c7
Record authentication key = 0533fd71f4119257361a3ff1469dd4e5
Record encryption key =     4feba89799be8ac3684fa2bb30ade0ea
                            51390e6d87dcf3627d2ee44493853abe
POLYVAL input =             489c8fde2be2cf97e74e932d4ed87d00
                            c9882e5386fd9f92ec00000000000000
                            78000000000000004800000000000000
POLYVAL result =            bf160bc9ded8c63057d2c38aae552fb4
POLYVAL result XOR nonce =  204127a8959f83a113a6244dae552fb4
... and masked =            204127a8959f83a113a6244dae552f34
Tag =                       c0fd3dc6628dfe55ebb0b9fb2295c8c2
Initial counter =           c0fd3dc6628dfe55ebb0b9fb2295c8c2
Result (25 bytes) =         0df9e308678244c44bc0fd3dc6628dfe
                            55ebb0b9fb2295c8c2


Plaintext (12 bytes) =      1db2316fd568378da107b52b
AAD (20 bytes) =            0da55210cc1c1b0abde3b2f204d1e9f8
                            b06bc47f
Key =                       a44102952ef94b02b805249bac80e6f6
                            1455bfac8308a2d40d8c845117808235
Nonce =                     5c9e940fea2f582950a70d5a
Record authentication key = 64779ab10ee8a280272f14cc8851b727
Record encryption key =     25f40fc63f49d3b9016a8eeeb75846e0
                            d72ca36ddbd312b6f5ef38ad14bd2651
POLYVAL input =             0da55210cc1c1b0abde3b2f204d1e9f8
                            b06bc47f000000000000000000000000
                            1db2316fd568378da107b52b00000000
                            a0000000000000006000000000000000
POLYVAL result =            cc86ee22c861e1fd474c84676b42739c
POLYVAL result XOR nonce =  90187a2d224eb9d417eb893d6b42739c
... and masked =            90187a2d224eb9d417eb893d6b42731c
Tag =                       404099c2587f64979f21826706d497d5
Initial counter =           404099c2587f64979f21826706d497d5
Result (28 bytes) =         8dbeb9f7255bf5769dd56692404099c2
                            587f64979f21826706d497d5


Plaintext (15 bytes) =      21702de0de18baa9c9596291b08466
AAD (25 bytes) =            f37de21c7ff901cfe8a69615a93fdf7a
                            98cad481796245709f
Key =                       9745b3d1ae06556fb6aa7890bebc18fe
                            6b3db4da3d57aa94842b9803a96e07fb
Nonce =                     6de71860f762ebfbd08284e4
Record authentication key = 27c2959ed4daea3b1f52e849478de376
Record encryption key =     307a38a5a6cf231c0a9af3b527f23a62
                            e9a6ff09aff8ae669f760153e864fc93
POLYVAL input =             f37de21c7ff901cfe8a69615a93fdf7a
                            98cad481796245709f00000000000000
                            21702de0de18baa9c9596291b0846600
                            c8000000000000007800000000000000
POLYVAL result =            c4fa5e5b713853703bcf8e6424505fa5
POLYVAL result XOR nonce =  a91d463b865ab88beb4d0a8024505fa5
... and masked =            a91d463b865ab88beb4d0a8024505f25
Tag =                       b3080d28f6ebb5d3648ce97bd5ba67fd
Initial counter =           b3080d28f6ebb5d3648ce97bd5ba67fd
Result (31 bytes) =         793576dfa5c0f88729a7ed3c2f1bffb3
                            080d28f6ebb5d3648ce97bd5ba67fd


Plaintext (18 bytes) =      b202b370ef9768ec6561c4fe6b7e7296
                            fa85
AAD (30 bytes) =            9c2159058b1f0fe91433a5bdc20e214e
                            ab7fecef4454a10ef0657df21ac7
Key =                       b18853f68d833640e42a3c02c25b6486
                            9e146d7b233987bddfc240871d7576f7
Nonce =                     028ec6eb5ea7e298342a94d4
Record authentication key = 670b98154076ddb59b7a9137d0dcc0f0
Record encryption key =     78116d78507fbe69d4a820c350f55c7c
                            b36c3c9287df0e9614b142b76a587c3f
POLYVAL input =             9c2159058b1f0fe91433a5bdc20e214e
                            ab7fecef4454a10ef0657df21ac70000
                            b202b370ef9768ec6561c4fe6b7e7296
                            fa850000000000000000000000000000
                            f0000000000000009000000000000000
POLYVAL result =            4e4108f09f41d797dc9256f8da8d58c7
POLYVAL result XOR nonce =  4ccfce1bc1e6350fe8b8c22cda8d58c7
... and masked =            4ccfce1bc1e6350fe8b8c22cda8d5847
Tag =                       454fc2a154fea91f8363a39fec7d0a49
Initial counter =           454fc2a154fea91f8363a39fec7d0ac9
Result (34 bytes) =         857e16a64915a787637687db4a951963
                            5cdd454fc2a154fea91f8363a39fec7d
                            0a49


Plaintext (21 bytes) =      ced532ce4159b035277d4dfbb7db6296
                            8b13cd4eec
AAD (35 bytes) =            734320ccc9d9bbbb19cb81b2af4ecbc3
                            e72834321f7aa0f70b7282b4f33df23f
                            167541
Key =                       3c535de192eaed3822a2fbbe2ca9dfc8
                            8255e14a661b8aa82cc54236093bbc23
Nonce =                     688089e55540db1872504e1c
Record authentication key = cb8c3aa3f8dbaeb4b28a3e86ff6625f8
Record encryption key =     02426ce1aa3ab31313b0848469a1b5fc
                            6c9af9602600b195b04ad407026bc06d
POLYVAL input =             734320ccc9d9bbbb19cb81b2af4ecbc3
                            e72834321f7aa0f70b7282b4f33df23f
                            16754100000000000000000000000000
                            ced532ce4159b035277d4dfbb7db6296
                            8b13cd4eec0000000000000000000000
                            1801000000000000a800000000000000
POLYVAL result =            ffd503c7dd712eb3791b7114b17bb0cf
POLYVAL result XOR nonce =  97558a228831f5ab0b4b3f08b17bb0cf
... and masked =            97558a228831f5ab0b4b3f08b17bb04f
Tag =                       9d6c7029675b89eaf4ba1ded1a286594
Initial counter =           9d6c7029675b89eaf4ba1ded1a286594
Result (37 bytes) =         626660c26ea6612fb17ad91e8e767639
                            edd6c9faee9d6c7029675b89eaf4ba1d
                            ed1a286594
			    



Plaintext (32 bytes) =      00000000000000000000000000000000
                            4db923dc793ee6497c76dcc03a98e108
AAD (0 bytes) =
Key =                       00000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     000000000000000000000000
Record authentication key = dc95c078a24089895275f3d86b4fb868
Record encryption key =     779b38d15bffb63d39d6e9ae76a9b2f3
                            75d11b0e3a68c422845c7d4690fa594f
POLYVAL input =             00000000000000000000000000000000
                            4db923dc793ee6497c76dcc03a98e108
                            00000000000000000001000000000000
POLYVAL result =            7367cdb411b730128dd56e8edc0eff56
POLYVAL result XOR nonce =  7367cdb411b730128dd56e8edc0eff56
... and masked =            7367cdb411b730128dd56e8edc0eff56
Tag =                       ffffffff000000000000000000000000
Initial counter =           ffffffff000000000000000000000080
Result (48 bytes) =         f3f80f2cf0cb2dd9c5984fcda908456c
                            c537703b5ba70324a6793a7bf218d3ea
                            ffffffff000000000000000000000000


Plaintext (24 bytes) =      eb3640277c7ffd1303c7a542d02d3e4c
                            0000000000000000
AAD (0 bytes) =
Key =                       00000000000000000000000000000000
                            00000000000000000000000000000000
Nonce =                     000000000000000000000000
Record authentication key = dc95c078a24089895275f3d86b4fb868
Record encryption key =     779b38d15bffb63d39d6e9ae76a9b2f3
                            75d11b0e3a68c422845c7d4690fa594f
POLYVAL input =             eb3640277c7ffd1303c7a542d02d3e4c
                            00000000000000000000000000000000
                            0000000000000000c000000000000000
POLYVAL result =            7367cdb411b730128dd56e8edc0eff56
POLYVAL result XOR nonce =  7367cdb411b730128dd56e8edc0eff56
... and masked =            7367cdb411b730128dd56e8edc0eff56
Tag =                       ffffffff000000000000000000000000
Initial counter =           ffffffff000000000000000000000080
Result (40 bytes) =         18ce4f0b8cb4d0cac65fea8f79257b20
                            888e53e72299e56dffffffff00000000
                            0000000000000000';
			    	

	
	$x=new AES_GCM_SIV;

	$n=0;
	
	$t=time();
	
	foreach (array_slice(explode("Plaintext",$test_vectors),1) as $tvector)
		{					
		$tvector=str_replace(array("\n","\x0a","\x0d"),"*",$tvector);

		echo "----------------------------------------TEST CASE $n \n\n";
				
		$text	=str_replace(array("*"," "),"",trim(explode("AAD",explode(") =",$tvector)[1])[0]));
		$A	=str_replace(array("*"," "),"",trim(explode("Key",explode("=",explode("AAD",$tvector)[1])[1])[0]));
		$key	=str_replace(array("*"," "),"",trim(explode("Nonce",explode("Key =",$tvector)[1])[0]));
		$nonce	=str_replace(array("*"," "),"",trim(explode("Record",explode("Nonce =",$tvector)[1])[0]));
		$tag	=str_replace(array("*"," "),"",trim(explode("Initial",explode("Tag =",$tvector)[1])[0]));
		$result	=str_replace(array("*"," "),"",trim(explode("=",explode("Result",$tvector)[1])[1]));
		
				
		echo "Plaintext 		".$text."\n";
		echo "AAD       		".$A."\n";
		echo "Key       		".$key."\n";
		echo "Nonce     		".$nonce."\n";
		
		echo "Tag       		".$tag."\n";
		echo "Result    		".$result."\n\n";
			
		++$n;
		
		$x->init("gcm",$key,$nonce,16);
			
		$C = $x->AES_GCM_SIV_encrypt($text,$A);
		
		echo "Computed tag 	".substr($C,-32)."\n";
		echo "Computed result ".$C."\n";
		echo "Computed dcrypt ".$x->AES_GCM_SIV_decrypt($C,$A)."\n\n";		
		}
	echo time()-$t;
	}

check_AES_GCM_SIV();	