/**
 ******************************************************************************
 * @project	
 *		SchoolNet
 * @author  			
 *		
 * @creationdate   
 *		
 * @lastmodifydate
 *		Jul 23, 2016
 * @verify
 *		
 * @verifydate
 * 
 * @company
 *		
 ******************************************************************************
 * @brief   
 *		
 * @attention
 *		
 ******************************************************************************
 */

/*=====================================
 Include headers
 =====================================*/
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "EAPOL.h"
#include "md5.h"

/*=====================================
 Variables definition
 =====================================*/
char AuthorityUserName[ 13 ];
char AuthorityPassword[ 13 ];

pthread_t EAPOL_CaptureID;
pthread_cond_t EAPOL_Cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t EAPOL_Mutex = PTHREAD_MUTEX_INITIALIZER;

libnet_t* Eth0Device = NULL;
char Eth0DeviceName[] =
{ "eth0" };
struct in_addr Eth0_IP;
uint8_t* Eth0MacAddress = NULL;
bpf_u_int32 Eth0_NetMask;
bpf_u_int32 Eth0_Net;
pcap_t *Eth0_Handle = NULL;

uint8_t EAPOLNearestMacAddress[] =
{ 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 };
uint8_t EAPOL_IdentityServerMAC[] =
{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

char ErrorBuffer[ 256 ];
char filter_exp[ 128 ];
struct bpf_program fp;
pcap_if_t* AllNIC = NULL;

int EAPOL_State;
int EAPOL_CurrentID = 0;
int EAPOL_RemoteID = 0;
int EAPOL_RemoteCode = 0;
bool EAPOL_MessagesIsHandled = true;
bool EAPOL_MessagesIsHeartbeat = false;

uint8_t EAPOL_RequestMD5ValueSize;
uint8_t EAPOL_RequestMD5Value[ 256 ];

/*=====================================
 Functions definition
 =====================================*/
bool EAPOL_InitialDevice();
void EAPOL_PrintOutNetworkStatus();
uint8_t* EAPOL_GetDeviceMac( libnet_t* device );

void EAPOL_GotPacket( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void *EAPOL_CapturingPackages( void *arg );
bool EAPOL_AuthorityThreadCreate();
bool EAPOL_StopAuthorityThread();

bool EAPOL_CreateStartOrLogoffFrame( uint8_t* ether_frame, uint8_t *eapol_src_mac, uint8_t *eapol_dst_mac, uint8_t flag );
bool EAPOL_SendStartFrame();
bool EAPOL_SendLogoffFrame();
void EAPOL_Start();
void EAPOL_Logoff();

bool EAPOL_CreateResponseIdentityFrame( uint8_t* ether_frame, uint8_t *eapol_src_mac, uint8_t *eapol_dst_mac, char *user_name, struct in_addr *ip );
bool EAPOL_SendResponseIdentityFrame();
void EAPOL_ResponseIdentity();

bool EAPOL_CreateResponseMD5ChallengeFrame( uint8_t* ether_frame, uint8_t *eapol_src_mac, uint8_t *eapol_dst_mac, char *user_name, char *password, struct in_addr *ip, uint8_t *md5_value,
        uint8_t md5_valuesize );
bool EAPOL_SendResponseMD5ChallengeFrame();
void EAPOL_ResponseMD5Challenge();

void EAPOL_ResponseHeartbeat();

/*=====================================
 Implementation of functions
 =====================================*/

bool EAPOL_InitialDevice()
{
	uint32_t TemperoryUnit32Data;

	Eth0Device = libnet_init( LIBNET_LINK_ADV, Eth0DeviceName, ErrorBuffer );
	Eth0MacAddress = EAPOL_GetDeviceMac( Eth0Device );
	if( Eth0MacAddress == NULL )
	{
		printf( "Error on getting MAC of eth0.\n" );
		return false;
	}

	if( pcap_lookupnet( Eth0DeviceName, &Eth0_Net, &Eth0_NetMask, ErrorBuffer ) == -1 )
	{
		printf( "Error on getting IP and Netmask for eth0.\nMessage: %s\n", ErrorBuffer );
		return false;
	}

	if( pcap_findalldevs( &AllNIC, ErrorBuffer ) == -1 )
	{
		printf( "Error on getting all NIC informations.\nMessage: %s\n", ErrorBuffer );
		return false;
	}

	for( pcap_if *NIC = AllNIC; NIC; NIC = NIC->next )
	{
		if( strcmp( NIC->name, Eth0DeviceName ) != 0 )
		{
			continue;
		}

		if( NIC->addresses == NULL )
		{
			printf( "Error on getting IP of eth0." );
			return false;
		}

		for( pcap_addr *NICAddress = NIC->addresses; NICAddress; NICAddress = NICAddress->next )
		{
			TemperoryUnit32Data = ( ( ( struct sockaddr_in* )( NICAddress->addr ) )->sin_addr.s_addr & Eth0_NetMask );
			if( TemperoryUnit32Data != Eth0_Net )
			{
				continue;
			}

			Eth0_IP.s_addr = ( ( struct sockaddr_in* )( NICAddress->addr ) )->sin_addr.s_addr;
		}
	}

	Eth0_Handle = pcap_open_live( Eth0DeviceName, BUFSIZ, 1, 3000, ErrorBuffer );
	if( Eth0_Handle == NULL )
	{
		printf( "Error for pcap_open_live.\n" );
		return false;
	}
	printf( "Open live for eth0 successfully.\n" );

	if( pcap_datalink( Eth0_Handle ) != DLT_EN10MB )
	{
		printf( "Error for pcap_datalink\n" );
		pcap_close( Eth0_Handle );
		libnet_destroy( Eth0Device );
		return 0;
	}
	printf( "Check data link for eth0 done!\n" );

	sprintf( filter_exp, "(ether proto 0x888e ) and ( ether dst %02X:%02X:%02X:%02X:%02X:%02X )", Eth0MacAddress[ 0 ], Eth0MacAddress[ 1 ], Eth0MacAddress[ 2 ], Eth0MacAddress[ 3 ],
	        Eth0MacAddress[ 4 ], Eth0MacAddress[ 5 ] );

	if( pcap_compile( Eth0_Handle, &fp, filter_exp, 0, Eth0_Net ) == -1 )
	{
		printf( "Error for pcap_compile.\nMessages : %s\n", pcap_geterr( Eth0_Handle ) );
		return false;
	}
	printf( "Compile rules for eth0 done!\n" );

	if( pcap_setfilter( Eth0_Handle, &fp ) == -1 )
	{
		printf( "Error for pcap_setfileter.\n" );
		return false;
	}
	printf( "Set filter for eth0 done!\n" );

	return true;
}

void EAPOL_PrintOutNetworkStatus()
{
	uint8_t TemperoryUint8Data;

	printf( "\nMAC of eth0 : " );
	for( int i = 0; i < ETHER_ADDR_LEN; ++i )
	{
		printf( ( i == ETHER_ADDR_LEN - 1 ? "%02X\n" : "%02X:" ), Eth0MacAddress[ i ] );
	}

	printf( "Net of eth0 : " );
	for( int i = 0; i < 4; ++i )
	{
		TemperoryUint8Data = ( ( Eth0_Net >> ( i * 8 ) ) & 0x000000FF );
		printf( ( i == 3 ? "%d\n" : "%d." ), TemperoryUint8Data );
	}

	printf( "NetMask of eth0 : " );
	for( int i = 0; i < 4; ++i )
	{
		TemperoryUint8Data = ( ( Eth0_NetMask >> ( i * 8 ) ) & 0x000000FF );
		printf( ( i == 3 ? "%d\n" : "%d." ), TemperoryUint8Data );
	}

	printf( "IP of eth0 : " );
	printf( "%s\n", inet_ntoa( Eth0_IP ) );
	printf( "\n" );
}

uint8_t* EAPOL_GetDeviceMac( libnet_t* device )
{
	uint8_t* return_mac = NULL;

	if( device == NULL )
		return NULL;

	struct libnet_ether_addr* Ether_Address;
	Ether_Address = libnet_get_hwaddr( device );
	return_mac = ( uint8_t* )malloc( ETHER_ADDR_LEN );
	if( return_mac == NULL )
		return NULL;

	memcpy( return_mac, Ether_Address->ether_addr_octet, ETHER_ADDR_LEN );
	return return_mac;
}

bool EAPOL_CreateStartOrLogoffFrame( uint8_t* ether_frame, uint8_t *eapol_src_mac, uint8_t *eapol_dst_mac, uint8_t flag )
{
	if( ether_frame == NULL )
	{
		return false;
	}

	if( eapol_src_mac == NULL || eapol_dst_mac == NULL )
	{
		return false;
	}

	if( ( flag != EAPOL_FLAG_START ) && ( flag != EAPOL_FLAG_LOGOFF ) )
	{
		return false;
	}

	Ethernet_Header *_ethernet_header = ( Ethernet_Header * )ether_frame;

	memcpy( _ethernet_header->DestinationMAC, eapol_dst_mac, ETHER_ADDR_LEN );
	memcpy( _ethernet_header->SourceMAC, eapol_src_mac, ETHER_ADDR_LEN );
	_ethernet_header->EtherType = htons( 0x888e );

	EAPOL_FrameHeader *_eapol_frameheader = ( EAPOL_FrameHeader* )( ether_frame + sizeof(Ethernet_Header) );
	_eapol_frameheader->Version = 0x01;
	_eapol_frameheader->Type = flag;
	_eapol_frameheader->Length = 0;

#if 0
	for( int i = 0; i < EAPOL_START_FRAME_LENGTH; ++i )
	{
		printf( ( i % 16 ) == 15 ? "%02X\n" : "%02X ", ether_frame[ i ] );
	}
#endif

	return true;
}

bool EAPOL_SendFrame( libnet_t *device, uint8_t *ether_frame, int frame_size )
{
	/*
	 if( ether_frame[ 23 ] == 0xcd )
	 {
	 ether_frame[ 23 ] = 0x00;
	 }
	 */

	if( libnet_write_link( device, ether_frame, frame_size ) == -1 )
	{
		return false;
	}

	return true;
}

void EAPOL_GotPacket( u_char *args, const struct pcap_pkthdr *header, const u_char *packet )
{

#if 0
	printf( "\npacket length = %d\n", header->len );
	printf( "packet = \n" );

	for( unsigned int i = 0; i < header->len; ++i )
	{
		printf( ( i % 16 ) == 15 ? "%02X\n" : "%02X ", packet[ i ] );
	}
	printf( "\n" );
#endif

	if( EAPOL_MessagesIsHandled == false )
	{
		printf( "Old Messages is not handled.\n" );
		return;
	}

	Ethernet_Header *_ethernet_header = ( Ethernet_Header* )packet;
	EAPOL_FrameHeader *_eapol_frame_header = ( EAPOL_FrameHeader* )( packet + sizeof(Ethernet_Header) );

	if( _eapol_frame_header->Type != 0x00 )
	{
		printf( "EAPOL_Type is not equate to 0x00. Type - %d\n", _eapol_frame_header->Type );
		return;
	}

	EAP_FrameHeader *_eap_frame_header = ( EAP_FrameHeader* )( packet + sizeof(Ethernet_Header) + sizeof(EAPOL_FrameHeader) );
	uint8_t *_eap_data = ( uint8_t* )( &( _eap_frame_header->Type ) + 1 );

	EAPOL_RemoteID = _eap_frame_header->Id;
	EAPOL_RemoteCode = _eap_frame_header->Code;
	EAPOL_MessagesIsHeartbeat = false;

	switch( _eap_frame_header->Code )
	{
		case EAP_CODE_REQUEST:
		{
			if( _eap_frame_header->Type == EAP_TYPE_IDENTITY )
			{
				printf( "Recieve messages: Request Identity.\n" );
				memcpy( EAPOL_IdentityServerMAC, _ethernet_header->SourceMAC, 6 );
				EAPOL_MessagesIsHeartbeat = true;
			}
			else if( _eap_frame_header->Type == EAP_TYPE_MD5_CHANLLENGE )
			{
				printf( "Recieve messages: Request MD5-Chanllenge EAP.\n" );
				EAPOL_RequestMD5ValueSize = _eap_data[ 0 ];
				memcpy( EAPOL_RequestMD5Value, _eap_data + 1, EAPOL_RequestMD5ValueSize );
			}
			else
			{
				printf( "Recieve messages: Unknown EAP Type - %d\n", _eap_frame_header->Type );
			}

			break;
		}

		case EAP_CODE_SUCCESS:
		{
			printf( "Recieve messages: Success.\n" );
			break;
		}

		case EAP_CODE_FAILURE:
		{
			printf( "Recieve messages: Failure.\n" );
			break;
		}

		default:
		{
			printf( "Recieve messages: Unknown EAP Code - %d\n", _eap_frame_header->Code );
			break;
		}
	}

	EAPOL_MessagesIsHandled = false;
	pthread_mutex_lock( &EAPOL_Mutex );
	pthread_cond_signal( &EAPOL_Cond );
	pthread_mutex_unlock( &EAPOL_Mutex );

}

void *EAPOL_CapturingPackages( void *arg )
{
	printf( "Begin to capture packets.\n" );
	if( pcap_loop( Eth0_Handle, 0, EAPOL_GotPacket, NULL ) < 0 )
	{
		printf( "Error for pcap_loop.\n" );
		return ( void* )0;
	}

	printf( "End of pcap_loop.\n" );

	return ( void* )0;
}

bool EAPOL_SendStartFrame()
{
	uint8_t frame[ EAPOL_START_FRAME_LENGTH ];
	memset( frame, 0, EAPOL_START_FRAME_LENGTH * sizeof(uint8_t) );

	if( EAPOL_CreateStartOrLogoffFrame( frame, Eth0MacAddress, EAPOLNearestMacAddress, EAPOL_FLAG_START ) == true )
	{
		printf( "Create Start Frame Successfully!\n" );
	}
	else
	{
		printf( "Create Start Frame Failed!\n" );
		return false;
	}

	if( EAPOL_SendFrame( Eth0Device, frame, EAPOL_START_FRAME_LENGTH ) == true )
	{
		printf( "Send start frame successfully.\n" );
	}
	else
	{
		printf( "Send start frame failed.\n" );
		return false;
	}

	return true;
}

bool EAPOL_AuthorityThreadCreate()
{
	int err = pthread_create( &EAPOL_CaptureID, NULL, EAPOL_CapturingPackages, NULL );
	if( err != 0 )
	{
		printf( "Error for creating authority thread.\n" );
		return false;
	}
	printf( "Create authority thread successfully.\n" );

	return true;
}

bool EAPOL_StopAuthorityThread()
{
	pcap_breakloop( Eth0_Handle );
	printf( "End of capture packets.\n" );

	if( pthread_cancel( EAPOL_CaptureID ) != 0 )
	{
		printf( "Error for cancel authority thread.\n" );
		return false;
	}
	printf( "Cancel authority thread Successfully.\n" );

	return true;
}

void EAPOL_Start()
{
	bool test_result;
	struct timespec tsp;
	struct timeval now;

	gettimeofday( &now, NULL );
	tsp.tv_sec = now.tv_sec + 10;
	tsp.tv_nsec = now.tv_usec * 1000;

	pthread_mutex_lock( &EAPOL_Mutex );
	test_result = EAPOL_SendStartFrame();
	if( pthread_cond_timedwait( &EAPOL_Cond, &EAPOL_Mutex, &tsp ) == ETIMEDOUT )
	{
		// Time out to wait for messages. Sleep 5 seconds and try again.
		printf( "Time out to wait for request identity.\n" );
		test_result = false;
	}
	pthread_mutex_unlock( &EAPOL_Mutex );

	if( test_result )
	{
		// Sent Successfully.
		if( ( EAPOL_RemoteID == 1 ) && ( EAPOL_RemoteCode == EAP_CODE_REQUEST ) )
		{
			EAPOL_State = EAPOL_STATE_RESPONSE_IDENTITY;
			EAPOL_CurrentID = EAPOL_RemoteID;
			EAPOL_MessagesIsHandled = true;
			return;
		}
	}

	// Sent Failed. Sleep 5 seconds and try again.
	EAPOL_State = EAPOL_STATE_LOGOFF;
	EAPOL_MessagesIsHandled = true;
	sleep( 5 );

}

bool EAPOL_CreateResponseIdentityFrame( uint8_t* ether_frame, uint8_t *eapol_src_mac, uint8_t *eapol_dst_mac, char *user_name, struct in_addr *ip )
{
	if( ether_frame == NULL || eapol_src_mac == NULL || eapol_dst_mac == NULL )
	{
		return false;
	}

	if( user_name == NULL || ip == NULL )
	{
		return false;
	}

	Ethernet_Header *_ethernet_header = ( Ethernet_Header * )ether_frame;

	memcpy( _ethernet_header->DestinationMAC, eapol_dst_mac, ETHER_ADDR_LEN );
	memcpy( _ethernet_header->SourceMAC, eapol_src_mac, ETHER_ADDR_LEN );
	_ethernet_header->EtherType = htons( 0x888e );

	EAPOL_FrameHeader *_eapol_frameheader = ( EAPOL_FrameHeader* )( ether_frame + sizeof(Ethernet_Header) );
	_eapol_frameheader->Version = 0x01;
	_eapol_frameheader->Type = 0;
	_eapol_frameheader->Length = htons( 26 );

	EAP_FrameHeader *_eap_frameheader = ( EAP_FrameHeader* )( ether_frame + sizeof(Ethernet_Header) + sizeof(EAPOL_FrameHeader) );
	_eap_frameheader->Code = EAP_CODE_RESPONSE;
	_eap_frameheader->Id = EAPOL_CurrentID;
	_eap_frameheader->Length = htons( 26 );
	_eap_frameheader->Type = EAP_TYPE_IDENTITY;

	char *_eap_data = ( char* )( &( _eap_frameheader->Type ) + 1 );
	char _ip[ 4 ];
	strcpy( _eap_data, user_name );
	_eap_data[ 12 ] = 0x00;
	_eap_data[ 13 ] = 0x44;
	_eap_data[ 14 ] = 0x61;
	_eap_data[ 15 ] = 0x00;
	_eap_data[ 16 ] = 0x00;

	for( int i = 0; i < 4; ++i )
	{
		_ip[ i ] = ( ( ip->s_addr >> ( 8 * i ) ) & 0x000000FF );
	}

	memcpy( _eap_data + 17, _ip, 4 );

#if 0
	printf( "response identity frame:\n" );
	for( int i = 0; i < EAPOL_RESPONSEIDENTITY_FRAME_LENGTH; ++i )
	{
		printf( ( i % 16 ) == 15 ? "%02X\n" : "%02X ", ether_frame[ i ] );
	}
#endif

	return true;
}

bool EAPOL_SendResponseIdentityFrame()
{
	uint8_t frame[ EAPOL_RESPONSEIDENTITY_FRAME_LENGTH ];
	memset( frame, 0, EAPOL_RESPONSEIDENTITY_FRAME_LENGTH * sizeof(uint8_t) );

	if( EAPOL_CreateResponseIdentityFrame( frame, Eth0MacAddress, EAPOL_IdentityServerMAC, AuthorityUserName, &Eth0_IP ) == true )
	{
		printf( "Create Response Identity Frame Successfully!\n" );
	}
	else
	{
		printf( "Create Response Identity Frame Failed!\n" );
		return false;
	}

	if( EAPOL_SendFrame( Eth0Device, frame, EAPOL_RESPONSEIDENTITY_FRAME_LENGTH ) == true )
	{
		printf( "Send Response Identity frame successfully.\n" );
	}
	else
	{
		printf( "Send Response Identity frame failed.\n" );
		return false;
	}

	return true;
}

void EAPOL_ResponseIdentity()
{
	bool test_result;
	struct timespec tsp;
	struct timeval now;

	gettimeofday( &now, NULL );
	tsp.tv_sec = now.tv_sec + 10;
	tsp.tv_nsec = now.tv_usec * 1000;

	pthread_mutex_lock( &EAPOL_Mutex );
	test_result = EAPOL_SendResponseIdentityFrame();
	if( pthread_cond_timedwait( &EAPOL_Cond, &EAPOL_Mutex, &tsp ) == ETIMEDOUT )
	{
		// Time out to wait for messages. Sleep 1 seconds and try again.
		printf( "Time out to wait for request MD5-challenge.\n" );
		test_result = false;
	}
	pthread_mutex_unlock( &EAPOL_Mutex );

	if( test_result )
	{

		if( ( EAPOL_RemoteID == 0 ) && ( EAPOL_RemoteCode == EAP_CODE_REQUEST ) )
		{
			// Sent Successfully.
			//printf( "Test successfully.\n" );
			EAPOL_State = EAPOL_STATE_RESPONSE_MD5_CHALLENGE;
			EAPOL_CurrentID = EAPOL_RemoteID;
			EAPOL_MessagesIsHandled = true;
			return;
		}
		printf( "ERROR in Response Identity.\nRemoteID=%d && RemoteCode=%d\n", EAPOL_RemoteID, EAPOL_RemoteCode );
	}

	// Sent Failed. Sleep 5 seconds and try again.
	EAPOL_State = EAPOL_STATE_LOGOFF;
	EAPOL_MessagesIsHandled = true;
	sleep( 5 );
}

bool EAPOL_SendLogoffFrame()
{
	uint8_t frame[ EAPOL_LOGOFF_FRAME_LENGTH ];
	memset( frame, 0, EAPOL_LOGOFF_FRAME_LENGTH * sizeof(uint8_t) );

	if( EAPOL_CreateStartOrLogoffFrame( frame, Eth0MacAddress, EAPOLNearestMacAddress, EAPOL_FLAG_LOGOFF ) == true )
	{
		printf( "Create Logoff Frame Successfully!\n" );
	}
	else
	{
		printf( "Create Logoff Frame Failed!\n" );
		return false;
	}

	if( EAPOL_SendFrame( Eth0Device, frame, EAPOL_LOGOFF_FRAME_LENGTH ) == true )
	{
		printf( "Send logoff frame successfully.\n" );
	}
	else
	{
		printf( "Send logoff frame failed.\n" );
		return false;
	}

	return true;
}

void EAPOL_Logoff()
{
	struct timespec tsp;
	struct timeval now;

	gettimeofday( &now, NULL );
	tsp.tv_sec = now.tv_sec + 10;
	tsp.tv_nsec = now.tv_usec * 1000;

	pthread_mutex_lock( &EAPOL_Mutex );
	EAPOL_SendLogoffFrame();
	if( pthread_cond_timedwait( &EAPOL_Cond, &EAPOL_Mutex, &tsp ) == ETIMEDOUT )
	{
		// Time out to wait for messages. Sleep 1 seconds and try again.
		printf( "Time out to wait for failure.\n" );
	}
	pthread_mutex_unlock( &EAPOL_Mutex );

	// Sent Failed. Sleep 5 seconds and try again.
	EAPOL_MessagesIsHandled = true;
	EAPOL_State = EAPOL_STATE_START;
	sleep( 5 );
}

bool EAPOL_CreateResponseMD5ChallengeFrame( uint8_t* ether_frame, uint8_t *eapol_src_mac, uint8_t *eapol_dst_mac, char *user_name, char *password, struct in_addr *ip, uint8_t *md5_value,
        uint8_t md5_valuesize )
{
	if( ether_frame == NULL || eapol_src_mac == NULL || eapol_dst_mac == NULL )
	{
		return false;
	}

	if( user_name == NULL || password == NULL || ip == NULL || md5_value == NULL )
	{
		return false;
	}

	Ethernet_Header *_ethernet_header = ( Ethernet_Header * )ether_frame;

	memcpy( _ethernet_header->DestinationMAC, eapol_dst_mac, ETHER_ADDR_LEN );
	memcpy( _ethernet_header->SourceMAC, eapol_src_mac, ETHER_ADDR_LEN );
	_ethernet_header->EtherType = htons( 0x888e );

	EAPOL_FrameHeader *_eapol_frameheader = ( EAPOL_FrameHeader* )( ether_frame + sizeof(Ethernet_Header) );
	_eapol_frameheader->Version = 0x01;
	_eapol_frameheader->Type = 0;
	_eapol_frameheader->Length = htons( 43 );

	EAP_FrameHeader *_eap_frameheader = ( EAP_FrameHeader* )( ether_frame + sizeof(Ethernet_Header) + sizeof(EAPOL_FrameHeader) );
	_eap_frameheader->Code = EAP_CODE_RESPONSE;
	_eap_frameheader->Id = EAPOL_CurrentID;
	_eap_frameheader->Length = htons( 43 );
	_eap_frameheader->Type = EAP_TYPE_MD5_CHANLLENGE;

	char *_eap_data = ( char* )( &( _eap_frameheader->Type ) + 1 );
	_eap_data[ 0 ] = 16;

	uint8_t identify[] =
	{ 0x00 };
	uint8_t md5result[ 16 ];
	char _ip[ 4 ];
	md5_state_t md5;

	md5_init( &md5 );
	md5_append( &md5, identify, 1 );
	md5_append( &md5, ( uint8_t* )password, 12 );
	md5_append( &md5, md5_value, ( int )md5_valuesize );
	md5_finish( &md5, md5result );

	memcpy( &( _eap_data[ 1 ] ), md5result, 16 );
	memcpy( _eap_data + 17, AuthorityUserName, 12 );

	_eap_data[ 29 ] = 0x00;
	_eap_data[ 30 ] = 0x44;
	_eap_data[ 31 ] = 0x61;
	_eap_data[ 32 ] = 0x2a;
	_eap_data[ 33 ] = 0x00;

	for( int i = 0; i < 4; ++i )
	{
		_ip[ i ] = ( ( ip->s_addr >> ( 8 * i ) ) & 0x000000FF );
	}

	memcpy( _eap_data + 34, _ip, 4 );

#if 0
	printf( "Request MD5 Size = %d\n", md5_valuesize );
	printf( "Request MD5 Value = \n" );
	for( int i = 0; i < 16; ++i )
	{
		printf( "%02X ", md5_value[ i ] );
	}
	printf( "\n" );

	printf( "response md5 challenge frame:\n" );
	for( int i = 0; i < EAPOL_RESPONSEMD5CHALLENGE_FRAME_LENGTH; ++i )
	{
		printf( ( i % 16 ) == 15 ? "%02X\n" : "%02X ", ether_frame[ i ] );
	}
#endif

	return true;
}

bool EAPOL_SendResponseMD5ChallengeFrame()
{
	uint8_t frame[ EAPOL_RESPONSEMD5CHALLENGE_FRAME_LENGTH ];
	memset( frame, 0, EAPOL_RESPONSEMD5CHALLENGE_FRAME_LENGTH * sizeof(uint8_t) );

	//if( EAPOL_CreateResponseIdentityFrame( frame, Eth0MacAddress, EAPOL_IdentityServerMAC, AuthorityUserName, &Eth0_IP ) == true )
	if( EAPOL_CreateResponseMD5ChallengeFrame( frame, Eth0MacAddress, EAPOL_IdentityServerMAC, AuthorityUserName, AuthorityPassword, &Eth0_IP, EAPOL_RequestMD5Value, EAPOL_RequestMD5ValueSize )
	        == true )
	{
		printf( "Create Response MD5 Challenge Frame Successfully!\n" );
	}
	else
	{
		printf( "Create Response MD5 Challenge Frame Failed!\n" );
		return false;
	}

	if( EAPOL_SendFrame( Eth0Device, frame, EAPOL_RESPONSEMD5CHALLENGE_FRAME_LENGTH ) == true )
	{
		printf( "Send Response MD5 Challenge frame successfully.\n" );
	}
	else
	{
		printf( "Send MD5 Challenge frame failed.\n" );
		return false;
	}

	return true;
}

void EAPOL_ResponseMD5Challenge()
{
	bool test_result;
	struct timespec tsp;
	struct timeval now;

	gettimeofday( &now, NULL );
	tsp.tv_sec = now.tv_sec + 10;
	tsp.tv_nsec = now.tv_usec * 1000;

	pthread_mutex_lock( &EAPOL_Mutex );
	test_result = EAPOL_SendResponseMD5ChallengeFrame();
	if( pthread_cond_timedwait( &EAPOL_Cond, &EAPOL_Mutex, &tsp ) == ETIMEDOUT )
	{
		// Time out to wait for messages. Sleep 1 seconds and try again.
		printf( "Time out to wait for request MD5-challenge.\n" );
		test_result = false;
	}
	pthread_mutex_unlock( &EAPOL_Mutex );

	if( test_result )
	{

		if( ( EAPOL_RemoteCode == EAP_CODE_SUCCESS ) )
		{
			// Sent Successfully.
			printf( "MD5 Challenge successfully.\n" );
			EAPOL_State = EAPOL_STATE_RESPONSE_HEARTBEAT;
			EAPOL_MessagesIsHandled = true;
			return;
		}
		printf( "ERROR in MD5 Challenge.\nRemoteCode=%d\n", EAPOL_RemoteCode );
	}

	// Sent Failed. Sleep 5 seconds and try again.
	EAPOL_State = EAPOL_STATE_LOGOFF;
	EAPOL_MessagesIsHandled = true;
	sleep( 5 );
}

void EAPOL_ResponseHeartbeat()
{

	pthread_mutex_lock( &EAPOL_Mutex );
	pthread_cond_wait( &EAPOL_Cond, &EAPOL_Mutex );
	pthread_mutex_unlock( &EAPOL_Mutex );

	if( EAPOL_MessagesIsHeartbeat == true )
	{
		EAPOL_CurrentID = EAPOL_RemoteID;
		EAPOL_MessagesIsHandled = true;
		EAPOL_SendResponseIdentityFrame();
		printf( "Heartbeat sent!\n" );
		return;
	}
	printf( "ERROR in Response Identity.\nRemoteID=%d && RemoteCode=%d\n", EAPOL_RemoteID, EAPOL_RemoteCode );

	// Sent Failed. Sleep 5 seconds and try again.
	EAPOL_State = EAPOL_STATE_LOGOFF;
	EAPOL_MessagesIsHandled = true;
	sleep( 5 );
}

