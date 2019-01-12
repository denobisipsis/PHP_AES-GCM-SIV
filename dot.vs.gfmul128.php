<?
/**
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
	$ab = gf128_dot($a , $b, $R); 		mul a,b and reduce modulo R
-second
	$r = gf128_dot($ab, $Ri, $R);		mul ab,Ri(=x^-128) and reduce modulo R
	

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

		H 	= 0x00000000000000000000000000000040;		    		 		    
		R	= 0xe1000000000000000000000000000000;
		
		no need to convert 
		
		1- a=strrev a
		2- b=mul b,H mod R
		3- r=mul a,b mod R
		
Compare speeds
;*/
	function convert($x) 
		{ 
		/*

		*/		
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
	 
	function dot($a,$b)
		{ 
		/**
		mod R=0x010000000000000000000000000000C2
		
		convert elements
		
		1- ab=mul a,b
		2- r=mul ab,Ri=0x01000000000000000000000000000492 		
		*/
		    $t=hrtime(true);
		    $Ri	=convert(u128_dec("01000000000000000000000000000492"));		 		    
		    $R 	=convert(u128_dec("010000000000000000000000000000C2"));		    				    
		    
		    $a	=convert(u128_dec($a));
		    $b	=convert(u128_dec($b));
		    		    
		    $ab	= gf128_dot($a , $b, $R);		    
		    $r	= convert(gf128_dot($ab, $Ri, $R));
		    
		    if ($r==0)  $bin = str_repeat("\0",16);		    
		    else 	$bin = gmp_export($r);
		    echo ((hrtime(true)-$t)/1000000)." ms ";
		    return $bin;
		}

	function dot2($a,$b)
		{   
		/**
		simplified dot
		
		no need to convert 
		
		mod R=0xe1000000000000000000000000000000
		
		1- a=strrev a
		2- b=mul b,H
		3- r=mul a,b 		
		*/
		    $t=hrtime(true);
		    $H 	= u128_dec("00000000000000000000000000000040");		    		 		    
		    $R	= u128_dec("e1000000000000000000000000000000");			    
		    
		    $a	= u128_dec(bin2hex(strrev(pack("H*",$a))));
		    
		    $b	= gf128_dot(u128_dec($b) , $H, $R);		    		    
		    $r  = gf128_dot($a , $b, $R);
		    
		    if ($r==0)  $bin = str_repeat("\0",16);		    
		    else 	$bin = strrev(gmp_export($r));
		    echo ((hrtime(true)-$t)/1000000)." ms ";
		    return $bin;
		}
/*********************************************************************************************************/
	 
	function gf128($X,$Y) 
		{
		$t=hrtime(true);
		for ($k=0;$k<16;$k++) 
			{
			$hbin[$k]=sprintf("%04b",$k);
			$h2bin[$hbin[$k]]=dechex($k);
			}
		
		$R 	= 225;//hexdec("e1");
		$p 	= str_repeat("0",128);						
		
		// masks to fast shifting, oring and anding
		
		$mask0 = str_repeat(sprintf("%08b",1),16);
		$mask1 = str_repeat("01111111",16);
		
		$Y=pack("H*",$Y)^str_repeat("\0",16);;
		
		/**
		Convert Y to an element of the binary galois field
		
		same as dot2 -> $b = gf128_dot(u128_dec($b) , $H, $R);
		*/
		
		$binY = str_replace($h2bin,$hbin,bin2hex($Y));
		
		$xLSB = $binY[7];				
		$binY = "0".substr($binY,0,-1)&$mask1|substr($binY&$mask0,15);				
		if ($xLSB)
			$binY = substr($binY,0,-8).decbin(bindec(substr($binY,-8)) ^ $R);
		$H = $p^$binY;

		$result="";foreach (str_split(bin2hex($H),2) as $z) $result.=$z[1];
		
		$binY = implode(array_reverse(str_split($result,8)));
		
		// Work X in binary-string form
									
		$binX = str_replace($h2bin,$hbin,$X);

		/*
		gfmul binX,binY
		 last binY bit is always 1, so strlen($binY)-1
		*/
		
		for($i = 0; $i < strlen($binY)-1; $i++) 
			{							 
			if ($binY[$i]) 						
				$p^=$binX;
			
			$xLSB = $binX[7];				
			$binX = "0".substr($binX,0,-1)&$mask1|substr($binX&$mask0,15);				
			if ($xLSB)
				$binX = substr($binX,0,-8).decbin(bindec(substr($binX,-8)) ^ $R);				 			
			}
		
		/**
		restore pure binary form of p (=result), making a last xoring
		
		same as dot2 -> $r  = gf128_dot($a , $b, $R);
		*/
		
		$result="";foreach (str_split(bin2hex($p^$binX),2) as $z) $result.=$z[1];
		
		$hex="";foreach (str_split($result,4) as $bin) $hex.=$h2bin[$bin];
		echo ((hrtime(true)-$t)/1000000)." ms ";	
		return $hex;			
		}

echo bin2hex(dot("66e94bd4ef8a2c3b884cfa59ca342b2e","ff000000000000000000000000000000"))."\n";	
echo bin2hex(dot2("66e94bd4ef8a2c3b884cfa59ca342b2e","ff000000000000000000000000000000"))."\n";
echo gf128("66e94bd4ef8a2c3b884cfa59ca342b2e","ff000000000000000000000000000000");