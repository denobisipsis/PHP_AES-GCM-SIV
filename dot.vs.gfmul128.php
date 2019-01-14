<?
/**

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



from draft https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.html

Polynomials in this document will be written as 16-byte values. 
For example, the sixteen bytes 01000000000000000000000000000492 
would represent the polynomial x^127 + x^124 + x^121 + x^114 + 1, 
which is also the value of x^-128 in this field.

10010010000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001

(1's are in positions 127,124,121,114 and 0)

$packed="";
foreach (str_split("10010010000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",8) as $z) $packed.=chr(bindec($z));
$hex=bin2hex(strrev($packed));

$Ri=$hex=01000000000000000000000000000492

irreducible polynomial: POLYVAL works modulo x^128 + x^127 + x^126 + x^121 + 1

11000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001

$R=$hex=010000000000000000000000000000C2


Then, dot makes 2 gf128 operations

- first 
	$ab = gf128_dot($a , $b, $R); 		mul a,b and reduce 		modulo 010000000000000000000000000000C2
-second
	Ri = 01000000000000000000000000000492
	$r = gf128_dot($ab, $Ri, $R);		mul ab,Ri(=x^-128) and reduce 	modulo 010000000000000000000000000000C2
	

function convert
	
		    ''' Polynomials in this field are converted to and from 128-bit strings
		    by taking the least-significant bit of the first byte to be the
		    coefficient of x^0, the most-significant bit of the first byte to the
		    the coefficient of x^7 and so on, until the most-significant bit of
		    the last byte is the coefficient of x^127.
		    '''	

so convert transform to an element of the binary galois field 2^128	


   
If a = 66e94bd4ef8a2c3b884cfa59ca342b2e and b =
   ff000000000000000000000000000000 then a+b =
   99e94bd4ef8a2c3b884cfa59ca342b2e, a*b =
   37856175e9dc9df26ebc6d6171aa0ae9 and 
   
   dot(a, b) = ebe563401e7e91ea3ad6426b8140c394.
   
   then dot(a,b) = gf128(a,b)
   
Also dot can be simplified

				    		 		    
		R	= e1000000000000000000000000000000;
		
		no need to convert 
		
		1- a=strrev a
		2- H 	= 40000000000000000000000000000000;
		   b=mul b,H mod e1000000000000000000000000000000
		3- r=strrev(mul a,b mod e1000000000000000000000000000000)	    
*/
		    
class Galois128
{	
	function __construct()
		{
		$this->hbin	= $this->h2bin = array();
		for ($k=0;$k<16;$k++) 
			{
			$this->hbin[$k]=sprintf("%04b",$k);
			$this->h2bin[$this->hbin[$k]]=dechex($k);
			}			
		}		    
	function convert($x) 
		{ 		
		$poly = 0;
		    for ($b=0;$b<16;$b++)
		    	{
		        $byte_val = 0;
		        for ($i=7; $i>-1; $i--)
			    {
		            $index = 127 - (8 * $b) - $i;				
		            $t_byte_val = bcmul(gmp_and(bcdiv($x,bcpow('2',$index)) , 1),bcpow('2',$i));
			    $byte_val = bcadd($t_byte_val,$byte_val) ;
			    }			
		        $poly = bcadd(bcmul($poly,256) , $byte_val) ;
			}
		    return $poly;
		}
		
	function gf128_dot($x, $y, $R)
		{
		    /*''' Multiplication in GF(2^128). 
		    The caller specifies the irreducible polynomial.
		    '''*/
		    $z = 0;
		    for ($i=127;$i>-1;$i--)
		        {
		        $z = $z ^ ($x * gmp_and(bcdiv($y,bcpow('2',$i)),1));      # if MSB is 0, XOR with 0, else XOR with x
		        $x = bcdiv($x,2) ^ (gmp_and($x , 1) * $R);     		  # shift and also reduce by R if overflow detected
			}
		
		    return $z;
		}			
	 function u128_dec($hex)
	 	{
	     	$dec = 0;
	     	$len = strlen($hex);
	     	for ($i = 1; $i <= $len; $i++)
	         	$dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));	
	     	return $dec;
	 	}
	 
	function dot_big_math($a,$b)
		{ 
		/*
		Working with long long elements
		
		mod R=0x010000000000000000000000000000C2
		
		convert elements
		
		1- ab=mul a,b
		2- r=mul ab,Ri=0x01000000000000000000000000000492 		
		*/
	
		    $Ri	= $this->convert($this->u128_dec("01000000000000000000000000000492"));		 		    
		    $R 	= $this->convert($this->u128_dec("010000000000000000000000000000C2"));		    				    
		  		    
		    $b	= $this->convert($this->u128_dec($b));
		    $X	= str_split($a,32);
		    
                    $i	= 0;$r = str_repeat("\0",16);	
		
		    while($i<sizeof($X))
			{
			$a	= $this->convert($this->u128_dec(bin2hex(pack("H*",$X[$i])^$r)));		    		    
		    	$ab	= $this->gf128_dot($a , $b, $R);		    
			$r	= gmp_Export($this->convert($this->gf128_dot($ab, $Ri, $R)));
		    	++$i;
		    	}

		    return bin2hex($r);
		}
	function dot2($a,$b)
		{   
		/*
		simplified dot
		
		no need to convert 
		
		mod R=0xe1000000000000000000000000000000
		
		1- a=strrev a
		2- b=mul b,H
		3- r=mul a,b 		
		*/
		 
		    $H 	= $this->u128_dec("40000000000000000000000000000000");		    		 		    
		    $R	= $this->u128_dec("e1000000000000000000000000000000");			    
		    
		    $b	= $this->gf128_dot($this->u128_dec($this->reverse($b)) , $H, $R);		    		    		    
		    $X	= str_split($a,32);
		    
                    $i	= 0;$r = str_repeat("\0",16);	
		
		    while($i<sizeof($X))
			{
			$a	= $this->u128_dec(bin2hex(strrev(pack("H*",$X[$i]))^$r));		    		    		    
			$r	= gmp_Export($this->gf128_dot($a, $b, $R));
		    	++$i;
		    	}

		    return bin2hex(strrev($r));
		}
/*********************************************************************************************************/
	function reverse($hex)
		{
		return implode(array_reverse(str_split($hex,2)));
		}
	function bstr($hex)
		{
		// from hex to binary string
		return str_replace($this->h2bin,$this->hbin,$hex);
		}
	function to128($bin)
		{
		$result="";foreach (str_split(bin2hex($bin),2) as $z) $result.=$z[1];
		return $result;
		}
	function bstrtohex($bin)
		{
		$hex="";foreach (str_split($this->to128($bin),4) as $bin) $hex.=dechex(bindec($bin));
		return $hex;
		}
	function mul($binX)
		{
		$mask0 	= str_repeat(sprintf("%08b",1),16);
		$mask1 	= str_repeat("01111111",16);
		// polynomial reduction
		$R 	= $this->bstr("000000000000000000000000000000e1");
		
		$xLSB 	= $binX[7];				
		$binX 	= "0".substr($binX,0,-1)&$mask1|substr($binX&$mask0,15);				
		if ($xLSB)
			$binX = $this->to128($binX^$R);
			
		return $binX;		
		}
				
	function PCLMULQDQ($X,$Y) 
		{
		// as defined in https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf		
		/*
		a = 			7b5b54657374566563746f725d53475d
		b = 			48692853686179295b477565726f6e5d
		PCLMULQDQ (a, b) = 	040229a09a5ed12e7e4e10da323506d2 
		
		little endian
		
		rbits =  Reflecting Bits 
		
		PCLMULQDQ (a, b) = rbits(GFMUL (rbits(a),rbits(b))) 
		*/

		$p     = str_repeat("0",128);						
		
		$binY  = strrev($this->bstr($Y));				
		$binX  = strrev($this->bstr($this->reverse($X)));
		
		for($i = 0; $i < 128; $i++) 
			{							 
			if ($binY[$i]) 						
				$p^=$binX;
			
			$binX = $this->mul($binX);				 			
			}
	
		return $this->reverse($this->bstrtohex(strrev($p)));				
		}	 
	function GFMUL($X,$Y) 
		{
		// as defined in https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
		/*
		Counter mode
		Data: 			952b2a56a5604ac0b32b6656a05b40b6
		Hash Key: 		dfa6bf4ded81db03ffcaff95f830f061
		Multiplication Result: 	da53eb0ad2c55bb64fc4802cc3feda60		
		*/

		$p     = str_repeat("0",128);						
		
		$binY  = $this->bstr($this->reverse($Y));
		$binY  = implode(array_reverse(str_split($binY,8)));			
		$binX  = $this->bstr($this->reverse($X));
		
		for($i = 0; $i < 128; $i++) 
			{							 
			if ($binY[$i]) 										
				$p^=$binX;
							
			$binX = $this->mul($binX);				 			
			}
	
		return $this->reverse($this->bstrtohex($p));			
		}

	function mulX_POLYVAL($X)
		{
		/*			   		   		
		multiplies X by bigendian(010000000000000000000000000000c2) 
		        and reduce modulo 000000000000000000000000000000e1 
			
		let H = 25629347589242761d31f826ba4b757b
		If we wished to calculate this
		   given only an implementation of POLYVAL then we would first calculate
		   the key for POLYVAL, 
		   mulX_POLYVAL(ByteReverse(H)) = f6ea96744df0633aec8424b18e26c54a
		*/
		
		$Ri = $this->reverse("010000000000000000000000000000c2");
		return $this->reverse($this->gfmul($X,$Ri));	
		}
				
	function mulX_GHASH($X)
		{
		/* 
		multiplies X by bigendian(40000000000000000000000000000000)
		        and reduce modulo 000000000000000000000000000000e1
			
		let H = 25629347589242761d31f826ba4b757b
		If we wished to calculate this
		   given only an implementation of GHASH then the key for GHASH would be
		   
		   mulX_GHASH(ByteReverse(H)) = dcbaa5dd137c188ebb21492c23c9b112
		*/
								
		$binX  = $this->mul($this->bstr($X));
		return $this->reverse($this->bstrtohex($binX));		
		}

	function dot_siv_ghash($X,$Y)
		{
		// as defined in https://www.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.txt
		/*
		   GHASH(H, X_1, ..., X_n) =
		   ByteReverse(POLYVAL(mulX_POLYVAL(ByteReverse(H)), ByteReverse(X_1),
		   ..., ByteReverse(X_n)))
		   		
		let H = 25629347589242761d31f826ba4b757b
		  X_1 = 4f4f95668c83dfb6401762bb2d01a262  
		  X_2 = d1a24ddd2721d006bbe45f20d3c9f362
		  
		GHASH(H, X_1, X_2)= bd9b3997046731fb96251b91f9c99d7a		
		*/
		$X	=str_split($X,32);
		$H	=$Y;
		$GHASH	=str_repeat("\0",16);
		
		$i	=0;			
		while($i<sizeof($X))
			{
			$GHASH=pack("H*",$this->gfmul(bin2hex($GHASH^pack("H*",$X[$i])),$H));			
			++$i;
			}
			
		return bin2hex($GHASH);					
		}
				
	function dot_siv_polyval($X,$Y)
		{
		// as defined in https://www.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.txt
		/*
		POLYVAL(H, X_1, ..., X_n) =
		   ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ...,
		   ByteReverse(X_n)))
		   
		
		let H = 25629347589242761d31f826ba4b757b
		  X_1 = 4f4f95668c83dfb6401762bb2d01a262  
		  X_2 = d1a24ddd2721d006bbe45f20d3c9f362
		  
		POLYVAL(H, X_1, X_2)= f7a3b47b846119fae5b7866cf5e5b77e			
		*/
		$X 	= str_split($X,32);
		$H 	= $this->mulX_GHASH($Y);
		$GHASH	= str_repeat("\0",16);	
		
		$i 	= 0;		
		while($i<sizeof($X))
			{
			$GHASH=pack("H*",$this->gfmul(bin2hex($GHASH^pack("H*",$this->reverse($X[$i]))),$H));
			++$i;
			}			
		return $this->reverse(bin2hex($GHASH));					
		}
}

$gf128=new Galois128;

echo " PCLMULQDQ 		".$gf128->PCLMULQDQ("7b5b54657374566563746f725d53475d","48692853686179295b477565726f6e5d")."\n";
echo " GFMUL     		".$gf128->GFMUL("952b2a56a5604ac0b32b6656a05b40b6","dfa6bf4ded81db03ffcaff95f830f061")."\n";
echo " mulX_POLYVAL 	".$gf128->mulX_POLYVAL(("25629347589242761d31f826ba4b757b"))."\n";
echo " mulX_GHASH 	".$gf128->mulX_GHASH(("25629347589242761d31f826ba4b757b"))."\n";
echo " GHASH   		".$gf128->dot_siv_ghash("4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362","25629347589242761d31f826ba4b757b")."\n";
/*
from https://www.ietf.org/id/draft-irtf-cfrg-gcmsiv-09.txt page 10

The latter halves of the ciphertext blocks are discarded and the
   remaining bytes are concatenated to form the per-message keys.  Thus
   the 
   
   message-authentication key is 310728d9911f1f3837b24316c3fab9a0
   
   and the message-encryption key is a4c5ae6249963279c100be4d7e2c6edd.

   The length block contains the encoding of the bit-lengths of the
   additional data and plaintext, respectively.  The string "example" is
   seven characters, thus 56 bits (or 0x38 in hex).  The string "Hello
   world" is 11 characters, or 88 = 0x58 bits.  Thus the length block is
   38000000000000005800000000000000.

   The input to POLYVAL is the padded additional data, padded plaintext
   and then the length block.  This is 
   
   6578616d706c6500000000000000000048656c6c6f20776f726c64000000000038000000000000005800000000000000
   
   based on the ASCII encoding of "example" (6578616d706c65) and of
   "Hello world" (48656c6c6f20776f726c64).

   Calling POLYVAL with the message-authentication key and the input
   above results in S_s = ad7fcf0b5169851662672f3c5f95138f.
*/

echo "\nComputing POLYVAL\n\n";
$input  ="6578616d706c6500000000000000000048656c6c6f20776f726c64000000000038000000000000005800000000000000";
$authkey="310728d9911f1f3837b24316c3fab9a0";

echo " Valid result   ad7fcf0b5169851662672f3c5f95138f\n";
$t=hrtime(true);
echo " POLYVAL 		".$gf128->dot_siv_polyval($input,$authkey)." ";
echo ((hrtime(true)-$t)/1000000)." ms (in binary mode)\n";
$t=hrtime(true);
echo " dot_big_math 	".$gf128->dot_big_math($input,$authkey)." ";
echo ((hrtime(true)-$t)/1000000)." ms (long long mode 1)\n";
$t=hrtime(true);
echo " dot_big_math2 	".$gf128->dot2($input,$authkey)." ";
echo ((hrtime(true)-$t)/1000000)." ms (long long mode 2)\n";

