

#include "socket.h"
#include "crypt_buffer.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#if 0
to compile this program, build it with the following options:
gcc -Wall -Wextra -pedantic -o main_2 crypt_buffer.c socket.c main_2.c -lpthread -lgcrypt

and then run it with ./main_2

expected output:

[ink@mtz crypt_buffer (master)]$ gcc -Wall -Wextra -pedantic -o main_2 crypt_buffer.c socket.c main_2.c -lpthread -lgcrypt
[ink@mtz crypt_buffer (master)]$ ./main_2
server started
client connecting ...
client connecting ...
client connecting ...
client connecting ...
client connected

secret message sent and received

[ink@mtz crypt_buffer (master)]$

#endif

void * client( void * e )
{
	socket_t s ;

	crypt_buffer_ctx ctx ;
	crypt_buffer_result r ;

	const char * secret = "\nsecret message sent and received\n" ;
	size_t len = strlen( secret ) + 1 ;

	if( e ){;}

	while( 1 ){

		puts( "client connecting ..." ) ;

		/*
		 * connecting to a server on port 2000 at IP address 127.0.0.1 (localhost)
		 */
		s = SocketNet( "127.0.0.1",2000 ) ;

		if( SocketConnect( &s ) ){
			puts( "client connected" ) ;
			break ;
		}else{
			sleep( 1 ) ;
		}
	}

	/*
	 * start encryption engine.
	 */
	crypt_buffer_init( &ctx,"xxx",3 ) ;

	/*
	 * encrypt message to send over the network
	 */
	crypt_buffer_encrypt( ctx,secret,len,&r ) ;

	/*
	 * send encrypted message
	 */
	SocketSendData( s,r.buffer,r.length ) ;

	/*
	 * close encryption engine and clean up its resources.
	 */
	crypt_buffer_uninit( &ctx ) ;

	/*
	 * close the socket and clean up its resources.
	 */
	SocketClose( &s ) ;

	return 0 ;
}

void * server( void * e )
{
	crypt_buffer_ctx ctx ;

	crypt_buffer_result r ;
	ssize_t n ;

	char * buffer = NULL ;

	socket_t t ;

	/*
	 * start a server at IP address 127.0.0.1 on port 2000
	 */
	socket_t s = SocketNet( "127.0.0.1",2000 ) ;

	if( e ){;}

	puts( "server started" ) ;

	/*
	 * reserve port 2000 for this server use.
	 */
	SocketBind( s ) ;

	/*
	 * delay the server to show client's attempts to connect
	 */
	sleep( 3 ) ;

	/*
	 * start waiting for client's connection.
	 */
	SocketListen( s ) ;

	/*
	 * accept client's connection
	 */
	t = SocketAccept( s ) ;

	/*
	 * read network data client sent.
	 */
	n = SocketGetData( t,&buffer ) ;

	if( buffer ){
		/*
		 * start decryption engine
		 */
		crypt_buffer_init( &ctx,"xxx",3 ) ;

		/*
		 * decrypt received data
		 */
		crypt_buffer_decrypt( ctx,buffer,n,&r ) ;

		/*
		 * use decrypted data
		 */
		puts( r.buffer ) ;

		/*
		 * shutdown decryption engine.
		 */
		crypt_buffer_uninit( &ctx ) ;

		/*
		 * free received data
		 */
		free( buffer ) ;
	}

	/*
	 * close used sockets
	 */
	SocketClose( &s ) ;
	SocketClose( &t ) ;

	return 0 ;
}

int main( int argc,char * argv[] )
{
	pthread_t clientthread ;
	pthread_t serverthread ;

	if( argc && argv ) {;}

	pthread_create( &clientthread,NULL,client,NULL ) ;
	pthread_create( &serverthread,NULL,server,NULL ) ;

	pthread_join( clientthread,NULL) ;
	pthread_join( serverthread,NULL ) ;

	return 0 ;
}
