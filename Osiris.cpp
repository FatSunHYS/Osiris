/**
 ******************************************************************************
 * @project	
 *		Osiris
 * @author  			
 *		
 * @creationdate   
 *		
 * @lastmodifydate
 *		Jul 24, 2016
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
#include "Osiris.h"
#include "EAPOL.h"

/*=====================================
 Variables definition
 =====================================*/

/*=====================================
 Functions definition
 =====================================*/

/*=====================================
 Implementation of functions
 =====================================*/

int main()
{

	// Read configuration files.
	strcpy( AuthorityUserName, "201520130769" );
	strcpy( AuthorityPassword, "201520130769" );

	// Initial the device.
	if( EAPOL_InitialDevice() == false )
	{
		if( Eth0_Handle )
		{
			pcap_close( Eth0_Handle );
		}

		if( Eth0Device )
		{
			libnet_destroy( Eth0Device );
		}

		return 0;
	}

	// Print out the messages of the eth0.
	EAPOL_PrintOutNetworkStatus();

	// Daemonize.

	// Begin to capture packets.
	if( EAPOL_AuthorityThreadCreate() == false )
	{
		pcap_close( Eth0_Handle );
		libnet_destroy( Eth0Device );
		return 0;
	}

	// let the new thread run first.
	sleep( 1 );

	EAPOL_State = EAPOL_STATE_START;

	while( EAPOL_State != EAPOL_STATE_FINISH )
	{
		switch( EAPOL_State )
		{
			case EAPOL_STATE_START:
			{
				EAPOL_Start();

				break;
			}

			case EAPOL_STATE_RESPONSE_IDENTITY:
			{
				EAPOL_ResponseIdentity();

				break;
			}

			case EAPOL_STATE_RESPONSE_MD5_CHALLENGE:
			{

				EAPOL_ResponseMD5Challenge();

				break;
			}

			case EAPOL_STATE_RESPONSE_HEARTBEAT:
			{
				EAPOL_ResponseHeartbeat();
				break;
			}

			case EAPOL_STATE_LOGOFF:
			{
				EAPOL_Logoff();
				break;
			}

			default:
			{
#if 1
				// Just for testing...
				EAPOL_State = EAPOL_STATE_FINISH;
#endif
				break;
			}
		}
	}

	sleep( 1 );

	// Stop capturing packages.
	if( EAPOL_StopAuthorityThread() == false )
	{
		pcap_close( Eth0_Handle );
		libnet_destroy( Eth0Device );
		return 0;
	}

	// End of the program.
	printf( "End of the Program. Exit...\n" );
	pcap_close( Eth0_Handle );
	libnet_destroy( Eth0Device );
	return 0;
}

