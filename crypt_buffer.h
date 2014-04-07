/*
 * copyright: 2014
 * name : mhogo mchungu
 * email: mhogomchungu@gmail.com
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

/*
 * This data structure hold result of the operation.
 */
typedef struct{
	size_t length ;
	void * buffer ;
}result ;

/*
 * This route takes a block of data encrypted by its encryption counter part and decrypt the block of data
 * The first argument is for internal use of the library and it is to be reused between decryption operations
 *
 * 1 is returned on success
 * 0 is returned on error
 */

int decrypt( char ** h,const void * buffer,u_int32_t buffer_size,
	     const char * password,size_t passphrase_size,result * r ) ;

/*
 * This routine takes a block of data and encrypts it
 * The first argument is for internal use of the library and it is to be reused between encryption operations
 * 1 is returned on success
 * 0 is returned on error
 */

int encrypt( char ** h,const void * buffer,u_int32_t buffer_size,
		     const char * password,size_t passphrase_size,result * r ) ;

/*
 * example use case
 */

#if 0

#include "crypt_buffer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int _status( char * e,char * f,int r )
{
	free( e ) ;
	free( f ) ;
	return r ;
}

int main( int argc,char * argv[] )
{
	char * encrypt_handle = NULL ;
	char * decrypt_handle = NULL ;

	result encrypt_result ;
	result decrypt_result ;

	/*
	 * Below two variables hold information about clear text data
	 */
	const char * data_to_encrypt = "abc" ;
	size_t data_to_encrypt_length = strlen( data_to_encrypt ) ;

	/*
	 * below two variables hold information about the key to be used for encrypted and decryption
	 */
	const char * password = "xxx" ;
	size_t password_length = strlen( password ) ;

	/*
	 * below two variables hold information about cipher text data
	 */
	const char * decrypted_data ;
	size_t       decrypted_data_size ;

	/*
	 * below two variables hold information about clear text data converted from cipher text data
	 */
	const char * encrypted_data ;
	size_t       encryped_data_size ;

	/*
	 * we dont need these two arguments
	 */
	if( argc && argv ){;}

	/*
	 * Encrypted a block of data using a given key
	 */
	if( encrypt( &encrypt_handle,data_to_encrypt,data_to_encrypt_length,password,password_length,&encrypt_result ) ){
		puts( "data encryption passed" ) ;
		encrypted_data     = encrypt_result.buffer ;
		encryped_data_size = encrypt_result.length ;
	}else{
		puts( "data encryption failed" ) ;
		return _status( encrypt_handle,decrypt_handle,1 ) ;
	}

	/*
	 * Given a block of cipher text,decrypt it using a given key
	 */
	if( decrypt( &decrypt_handle,encrypted_data,encryped_data_size,password,password_length,&decrypt_result ) ){
		puts( "data decryption passed" ) ;
		decrypted_data      = decrypt_result.buffer ;
		decrypted_data_size = decrypt_result.length ;
	}else{
		puts( "data decryption failed" ) ;
		return _status( encrypt_handle,decrypt_handle,1 ) ;
	}

	/*
	 * Here,we compare our original clear text and the clear text derived from cipher text to
	 * see if the conversion was successful or not
	 */

	if( strcmp( data_to_encrypt,decrypted_data ) == 0 ){
		if( data_to_encrypt_length == decrypted_data_size ){
			puts( "conversion successful" ) ;
			return _status( encrypt_handle,decrypt_handle,0 ) ;
		}else{
			puts( "conversion 1 failed" ) ;
			return _status( encrypt_handle,decrypt_handle,1 ) ;
		}
	}else{
		puts( "conversion 2 failed" ) ;
		return _status( encrypt_handle,decrypt_handle,1 ) ;
	}
}
#endif