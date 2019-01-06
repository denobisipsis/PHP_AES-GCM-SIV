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

	- AES Galois Counter Mode nonce misuse-resistant (GCM-SIV)
