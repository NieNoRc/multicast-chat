extern "C"
{
	#include "../../../unpv13e/lib/unp.h"//need modify
}
#include <signal.h>
#include <string>
#include <openssl/dh.h>
#include <openssl/des.h>
#include <pthread.h>
#include <map>
#define MCBUFFLEN 1024
#define IF_NAME "enp0s3"//need modify
#define IF_INDEX 2//need modify
#define PORT 9999
#define VERI_CODE_LEN 4
#define CMD_TYPE_KEYSYC 'k'
#define CMD_TYPE_EXIT 'q'
#define CMD_TYPE_FILE 'f'
#define CMD_TYPE_LIST 'l'
#define CMD_TYPE_ENABLE 'e'
#define CMD_TYPE_DISABLE 'd'
#define CMD_TYPE_HELP 'h'
#define MSG_TYPE_EXIT 0
#define MSG_TYPE_DHREQ 1
#define MSG_TYPE_DHREP 2
#define MSG_TYPE_FNAME 3
#define MSG_TYPE_FCONT 4
#define MSG_TYPE_FTAIL 5
#define MSG_TYPE_MSG 6 
#define DECRY_CHECK "abcd"
#define DHREQ_MID 256
struct mckey
{
	DES_cblock key;
	bool keyflg;
};
struct mcheader
{
	unsigned char mtype;
	unsigned short mlen;
};
struct cliParam
{
	FILE *f;
	int sockfd;
	SA * saddr;
};
struct servParam
{
	int sockfd;
	int sendfd;
	const SA* saddr;
};
void getselfIP(char *);
void  *clithr(void *);
void  *servthr(void *);
void  dg_cli(FILE *, int, SA *);
void  chat_server(int, int ,const SA *);
void dhreq(char *);
void genDHobj(DH *);
void sighandler(int);
void vericodeinsert(char *);
bool decryandveri(char *,char *,in_addr_t);
void displaykeytable();
void outputhelp();
