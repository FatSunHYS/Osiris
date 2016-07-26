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

#ifndef EAPOL_H_
#define EAPOL_H_

/*=====================================
 Include headers
 =====================================*/
#include <stdint.h>
#include <libnet.h>
#include <pcap.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <sys/time.h>

/*=====================================
 Global Constants
 =====================================*/
#define EAPOL_START_FRAME_LENGTH  0x60
#define EAPOL_LOGOFF_FRAME_LENGTH  0x60
#define EAPOL_RESPONSEIDENTITY_FRAME_LENGTH 0x60
#define EAPOL_RESPONSEMD5CHALLENGE_FRAME_LENGTH 0x60

#define EAPOL_FLAG_START 0x01
#define EAPOL_FLAG_LOGOFF 0x02

#define EAPOL_STATE_START 0
#define EAPOL_STATE_RESPONSE_IDENTITY 1
#define EAPOL_STATE_RESPONSE_MD5_CHALLENGE 2
#define EAPOL_STATE_RESPONSE_HEARTBEAT 3
#define EAPOL_STATE_LOGOFF 4
#define EAPOL_STATE_FINISH 5

#define EAP_CODE_REQUEST 1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS 3
#define EAP_CODE_FAILURE 4

#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_MD5_CHANLLENGE 4

/*=====================================
 Global Macro
 =====================================*/
struct Ethernet_Header
{
	uint8_t DestinationMAC[ ETHER_ADDR_LEN ];
	uint8_t SourceMAC[ ETHER_ADDR_LEN ];
	uint16_t EtherType;
};

struct EAPOL_FrameHeader
{

	uint8_t Version;
	uint8_t Type;
	uint16_t Length;
};

struct EAP_FrameHeader
{
	uint8_t Code;
	uint8_t Id;
	uint16_t Length;
	uint8_t Type;
};


/*=====================================
 Extern Variables
 =====================================*/
extern char AuthorityUserName[ 13 ];
extern char AuthorityPassword[ 13 ];

extern pthread_t EAPOL_CaptureID;
extern pthread_cond_t EAPOL_Cond;
extern pthread_mutex_t EAPOL_Mutex;

extern libnet_t* Eth0Device;
extern char Eth0DeviceName[];
extern struct in_addr Eth0_IP;
extern uint8_t* Eth0MacAddress;
extern bpf_u_int32 Eth0_NetMask;
extern bpf_u_int32 Eth0_Net;
extern pcap_t *Eth0_Handle;

extern uint8_t EAPOLNearestMacAddress[];

extern char ErrorBuffer[ 256 ];
extern char filter_exp[ 128 ];
extern struct bpf_program fp;
extern pcap_if_t* AllNIC ;

extern int EAPOL_State;

/*=====================================
 Extern Functions
 =====================================*/
extern bool EAPOL_InitialDevice();
extern void EAPOL_PrintOutNetworkStatus();
extern bool EAPOL_AuthorityThreadCreate();
extern bool EAPOL_StopAuthorityThread();

extern void EAPOL_Start();
extern void EAPOL_Logoff();
extern void EAPOL_ResponseIdentity();
extern void EAPOL_ResponseMD5Challenge();
extern void EAPOL_ResponseHeartbeat();

#endif /* EAPOL_H_ */
