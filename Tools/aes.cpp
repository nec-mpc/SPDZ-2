// (C) 2018 University of Bristol, Bar-Ilan University. See License.txt


#include "aes.h"

//THIS CODE PATH SHOULD NOT BE REACHED AS WE USE AESNI 

void aes_schedule( int nb, int nr, octet* k, uint* RK ) 
{
	
  //avoid werr
  (*k) = (octet) nb; 
   (*RK) = nr; 
 
  //empty
  exit(-100);
}


void aes_128_encrypt( octet* C, octet* M, uint* RK )
{
  (*C) = (octet) 0;
  (*M) = (octet) 0;
  (*RK) = 0; 
 
 //empty
  exit(-100);
 }


void aes_192_encrypt( octet* C, octet* M, uint* RK )
{
    //empty
  (*C) = (octet) 0;
  (*M) = (octet) 0;
  (*RK) = 0; 
  exit(-100);
  }


void aes_256_encrypt( octet* C, octet* M, uint* RK )
{
   //empty
   (*C) = (octet) 0;
  (*M) = (octet) 0;
  (*RK) = 0;   
  exit(-100);
  }
