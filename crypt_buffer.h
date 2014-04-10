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

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * This data structure hold result of the operation.
 */
typedef struct{
	void * buffer ;
	size_t length ;
}crypt_buffer_result ;

typedef struct crypt_buffer_ctx_1 * crypt_buffer_ctx ;

/*
 * create crypt buffer_context object.
 * The same context object can be used for both encryption and decryption.
 * 1 is returned on success.
 * 0 is returned on error.
 */
int crypt_buffer_init( crypt_buffer_ctx * ctx ) ;

/*
 * destroy crypt_buffer context object when done with it.
 */
void crypt_buffer_uninit( crypt_buffer_ctx * ctx ) ;

/*
 * This routine takes a block of data and encrypts it
 * The first argument is for internal use of the library and it is to be reused between encryption/decryption operations.
 * 1 is returned on success.
 * 0 is returned on error.
 */
int crypt_buffer_encrypt( crypt_buffer_ctx ctx,const void * buffer,u_int32_t buffer_size,
			  const void * password,size_t passphrase_size,crypt_buffer_result * r ) ;

/*
 * This routine takes a block of data encrypted by crypt_buffer_encrypt() decrypt it.
 * The first argument is for internal use of the library and it is to be reused between encryption/decryption operations.
 *
 * 1 is returned on success.
 * 0 is returned on error.
 */
int crypt_buffer_decrypt( crypt_buffer_ctx ctx,const void * buffer,u_int32_t buffer_size,
			  const void * password,size_t passphrase_size,crypt_buffer_result * r ) ;

/*
 * example use case using a complete workable program is below.
 */
#if 0

#include "crypt_buffer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void * _buffer ;
static size_t _buffer_size ;

static void sendData( const void * buffer,size_t buffer_size )
{
	_buffer = malloc( buffer_size ) ;
	_buffer = memcpy( _buffer,buffer,buffer_size ) ;
	_buffer_size = buffer_size ;
}

static void receiveEncryptedDataFromSomeWhere( void ** buffer,size_t * buffer_size )
{
	*buffer      = _buffer ;
	*buffer_size = _buffer_size ;
}

static void consumeDecryptedReceivedData( const void * buffer,size_t buffer_size )
{
	const char * x = buffer ;
	size_t i ;
	char e ;
	for( i = 0 ; i < buffer_size ; i++ ){
		e = *( x + i ) ;
		printf( "%c",e ) ;
	}
	printf( "\n" ) ;
}

static void encryptAndSendData( const void * data,size_t data_size,const char * key,size_t key_size )
{
	crypt_buffer_ctx ctx ;
	crypt_buffer_result r ;

	if( crypt_buffer_init( &ctx ) ){

		if( crypt_buffer_encrypt( ctx,data,data_size,key,key_size,&r ) ){
			/*
			* encryption succeeded,simulate sending encrypted data somewhere
			*/
			sendData( r.buffer,r.length ) ;
		}

		crypt_buffer_uninit( &ctx ) ;
	}
}

void decryptReceivedDataAndConsumeIt( const void * cipher_text_data,
				      size_t cipher_text_data_size,const char * key,size_t key_size )
{
	crypt_buffer_ctx ctx ;
	crypt_buffer_result r ;

	if( crypt_buffer_init( &ctx ) ){

		if( crypt_buffer_decrypt( ctx,cipher_text_data,cipher_text_data_size,key,key_size,&r ) ){
			/*
			 * decryption succeeded,
			 */
			/*
			 * This function simulates using of now decrypted data
			 */
			consumeDecryptedReceivedData( r.buffer,r.length ) ;
		}

		crypt_buffer_uninit( &ctx ) ;
	}
}

int main( int argc,char * argv[] )
{
	/*
	 * data to be encrypted before sending it somewhere.
	 */
	const char * data = "works as expected" ;
	size_t data_size  = strlen( data ) ;

	/*
	 * key to be used for encrypted and decryption
	 */
	const char * key = "xyz" ;
	size_t key_size = strlen( key ) ;

	void * cipher_buffer ;
	size_t cipher_buffer_size ;

	/*
	 * we dont need these two arguments
	 */
	if( argc && argv ){;}

	/*
	 * This function simulates encrypting data and sending it somewhere
	 */
	encryptAndSendData( data,data_size,key,key_size ) ;

	/*
	 * This function simulates receiving encrypted data.
	 */
	receiveEncryptedDataFromSomeWhere( &cipher_buffer,&cipher_buffer_size ) ;

	/*
	 * This function simulates data decryption received from somewhere.
	 */
	decryptReceivedDataAndConsumeIt( cipher_buffer,cipher_buffer_size,key,key_size ) ;

	/*
	 * clean up after simulation ;
	 *
	 */
	free( _buffer ) ;
	return 0 ;
}

#endif

#ifdef __cplusplus
}
#endif
