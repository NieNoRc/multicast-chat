#include "../headfiles/mcchat.h"
int ftflag;
bool exitflag;
DH *reqdh;
char selfip[16];
std::map <in_addr_t,struct mckey> keytable;
DES_cblock ivec;//initial vector for des
pthread_mutex_t mtx;
int main(int argc, char **argv)
{	

	signal(SIGINT, sighandler);
	exitflag=false;
	ftflag=true;
	int ret;
	int i;
	if (argc != 2)
		err_quit( "usage : main <multicast group ip address>");
	if(pthread_mutex_init(&mtx,NULL)!=0)
		err_quit("thread lock initialization failure");
	getselfIP(selfip);
	selfip[strlen(selfip)-1]=0;
	printf("selfip:%s\n",selfip);
	int recvsd,sendsd;
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	Inet_pton(AF_INET, argv[1], &servaddr.sin_addr);
	recvsd = Socket(AF_INET, SOCK_DGRAM, 0);
	sendsd = Socket(AF_INET, SOCK_DGRAM, 0);
	servParam prams;
	cliParam cliprams;
	pthread_t servtid,clitid;
	prams.sockfd=recvsd;
	prams.saddr=(const SA *) &servaddr;
	cliprams.f=stdin;
	cliprams.sockfd=prams.sendfd=sendsd;
	cliprams.saddr=(SA *) &servaddr;
	memset((char*)&ivec, 0, sizeof(ivec));
	reqdh=DH_new();
	genDHobj(reqdh);
	ret = pthread_create( &servtid, NULL, servthr, &prams );  
    if( ret != 0 ){  
        err_quit( "Create thread error!");  
    } 
    ret = pthread_create( &clitid, NULL, clithr, &cliprams );  
    if( ret != 0 ){  
        err_quit( "Create thread error!");    
    } 
    pthread_join(clitid,NULL);
	pthread_join(servtid,NULL);
	
	
	
}
