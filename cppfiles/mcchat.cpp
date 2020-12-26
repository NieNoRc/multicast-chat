#include "../headfiles/mcchat.h"
extern int ftflag;
extern bool exitflag;
extern DH *reqdh;
extern char selfip[16];
extern std::map <in_addr_t,struct mckey> keytable;
extern DES_cblock ivec;
extern pthread_mutex_t mtx;
void  dg_cli(FILE *fp, int sockfd, SA *pservaddr)//core function for transmit thread
{
	  
      DES_key_schedule ks;
      int fd,rdlen;
      unsigned short bnlen;
      mcheader hdr;
      char getline[MCBUFFLEN],sendline[MCBUFFLEN],crypline[MCBUFFLEN];
      char *filebf=(char *)malloc((8*((MCBUFFLEN-sizeof(mcheader))/8)-VERI_CODE_LEN)*sizeof(char));
      hdr.mtype=MSG_TYPE_DHREQ;
      hdr.mlen=MCBUFFLEN;
      bzero(sendline,MCBUFFLEN);
      memmove(sendline,&hdr,sizeof(struct mcheader));//default key exchange request transmission
      dhreq(sendline);
      sendto(sockfd, sendline, MCBUFFLEN, 0, pservaddr, sizeof(sockaddr_in));
      printf("input :%c for help\n",CMD_TYPE_HELP);
      while(Fgets(getline, 8*((MCBUFFLEN-sizeof(mcheader))/8)-VERI_CODE_LEN, fp) != NULL)//get input from user
      {
			bzero(sendline,MCBUFFLEN);
			bzero(crypline,MCBUFFLEN);
			if(getline[0]==':')
			{
				switch(getline[1])
				{
					case CMD_TYPE_LIST://list keys' states
						displaykeytable();
						break;
					case CMD_TYPE_KEYSYC://send a key exchange request
						exitflag=false;
						hdr.mtype=MSG_TYPE_DHREQ;
						hdr.mlen=MCBUFFLEN;
						bzero(sendline,MCBUFFLEN);
						memmove(sendline,&hdr,sizeof(struct mcheader));//put the header
						dhreq(sendline);
						sendto(sockfd, sendline, MCBUFFLEN, 0, pservaddr, sizeof(sockaddr_in));
						break;
					case CMD_TYPE_ENABLE://enable keys
						getline[strlen(getline)-1]=0;
						if(strcmp(getline+3,"all")==0)//enable all
						{
							pthread_mutex_lock(&mtx);//lock
							for(std::map <in_addr_t,struct mckey>::iterator ite=keytable.begin();ite!=keytable.end();++ite)//travel the key table and enable all entries
							{	
									(ite->second).keyflg=true;
									
							}
							pthread_mutex_unlock(&mtx);//unlock
						}
						else//enable an ip entry
						{
							in_addr_t eadr=inet_addr(getline+3);
							if(eadr==-1)
							{
								printf("ip address format error\n");
							}
							else
							{
								pthread_mutex_lock(&mtx);
								if(keytable.find(eadr)==keytable.end())
								{
									pthread_mutex_unlock(&mtx);
									printf("no entry\'s ip is %s\n",getline+3);
								}
								else
								{
									keytable[eadr].keyflg=true;
									pthread_mutex_unlock(&mtx);
								}
								
							}
						}
						break;
					case CMD_TYPE_DISABLE://disable keys, similar to enable
						getline[strlen(getline)-1]=0;
						if(strcmp(getline+3,"all")==0)
						{
							pthread_mutex_lock(&mtx);//lock
							for(std::map <in_addr_t,struct mckey>::iterator ite=keytable.begin();ite!=keytable.end();++ite)
							{	
									(ite->second).keyflg=false;
									
							}
							pthread_mutex_unlock(&mtx);//unlock
						}
						else
						{
							in_addr_t eadr=inet_addr(getline+3);
							if(eadr==-1)
							{
								printf("ip address format error\n");
							}
							else
							{
								pthread_mutex_lock(&mtx);
								if(keytable.find(eadr)==keytable.end())
								{
									pthread_mutex_unlock(&mtx);
									printf("no entry\'s ip is %s\n",getline+3);
								}
								else
								{
									keytable[eadr].keyflg=false;
									pthread_mutex_unlock(&mtx);
								}
								
							}
						}
						break;
					case CMD_TYPE_EXIT://quit command
						hdr.mtype=MSG_TYPE_EXIT;
						hdr.mlen=0;
						bzero(sendline,MCBUFFLEN);
						memmove(sendline,&hdr,sizeof(struct mcheader));
						sendto(sockfd, sendline, MCBUFFLEN, 0, pservaddr, sizeof(sockaddr_in));
						exitflag=true;
						break;
					case CMD_TYPE_FILE://file transmission command
						if(ftflag){
						ftflag=false;
						getline[strlen(getline)-1]=0;
						fd = open(getline+3, O_RDONLY); //open file
						if(-1 == fd)
						{
							printf("open file error or no such file\n");
						}
						else//send the file name message
						{
							
							hdr.mtype=MSG_TYPE_FNAME;
							hdr.mlen=strlen(getline+3);
							memmove(sendline,&hdr,sizeof(struct mcheader));
							memmove(crypline+VERI_CODE_LEN,getline+3,strlen(getline+3)+1);
							vericodeinsert(crypline);
							pthread_mutex_lock(&mtx);//lock
							for(std::map <in_addr_t,struct mckey>::iterator ite=keytable.begin();ite!=keytable.end();++ite)
							{	
								if((ite->second).keyflg)
								{
									if (DES_set_key_checked(&(ite->second.key), &ks) != 0)
									{
										printf("convert to key_schedule failed.\n");
									}
									else
										DES_ncbc_encrypt((unsigned char *)crypline, (unsigned char*)(sendline+sizeof(mcheader)),8*((MCBUFFLEN-sizeof(mcheader))/8), &ks, &ivec, DES_ENCRYPT);
									sendto(sockfd, sendline, MCBUFFLEN, 0, pservaddr, sizeof(sockaddr_in));
								}
							}
							pthread_mutex_unlock(&mtx);//unlock
							while(1)
							{
								hdr.mtype=MSG_TYPE_FCONT;
								hdr.mlen=8*((MCBUFFLEN-sizeof(mcheader))/8)-VERI_CODE_LEN;
								rdlen = read(fd, filebf, 8*((MCBUFFLEN-sizeof(mcheader))/8)-VERI_CODE_LEN); //read the content
								if(rdlen== -1)
								{
									printf("read file error\n");
								}
								if(rdlen< (8*((MCBUFFLEN-sizeof(mcheader))/8)-VERI_CODE_LEN)) //tail of file
								{   
									hdr.mtype=MSG_TYPE_FTAIL;
									hdr.mlen=rdlen;                                        
								}
								memmove(sendline,&hdr,sizeof(struct mcheader));
								memmove(crypline+VERI_CODE_LEN,filebf,hdr.mlen);
								vericodeinsert(crypline);
								pthread_mutex_lock(&mtx);//lock
								for(std::map <in_addr_t,struct mckey>::iterator ite=keytable.begin();ite!=keytable.end();++ite)
								{	
									if((ite->second).keyflg)
									{
										if (DES_set_key_checked(&(ite->second.key), &ks) != 0)
										{
											printf("convert to key_schedule failed.\n");
										}
										else
											DES_ncbc_encrypt((unsigned char *)crypline, (unsigned char*)(sendline+sizeof(mcheader)),8*((MCBUFFLEN-sizeof(mcheader))/8), &ks, &ivec, DES_ENCRYPT);
										sendto(sockfd, sendline, MCBUFFLEN, 0, pservaddr, sizeof(sockaddr_in));
									}
								}
								pthread_mutex_unlock(&mtx);//unlock
								memset(filebf, 0,8*((MCBUFFLEN-sizeof(mcheader)-VERI_CODE_LEN)/8));
								if(rdlen< (8*((MCBUFFLEN-sizeof(mcheader))/8)-VERI_CODE_LEN))      //tail of file
								{   
									close(fd);
									ftflag=true;
									printf("file transmittion has done!\n");                                
									break;
								}
								usleep(500);
							}
						}}
						else
						{
							printf("there is a file being transferred now in the channel, please wait.\n");
						}
						break;
					case CMD_TYPE_HELP://display help information
						outputhelp();
						break;
					default:
						printf("no such command\n");
						break;
				}
				
			}
			else//normal message
			{
				if(getline[0]=='\n')
					break;
				hdr.mtype=MSG_TYPE_MSG;
				hdr.mlen=strlen(getline);
				memmove(sendline,&hdr,sizeof(struct mcheader));
				memmove(crypline+VERI_CODE_LEN,getline,strlen(getline)+1);
				vericodeinsert(crypline);
				pthread_mutex_lock(&mtx);//lock
				for(std::map <in_addr_t,struct mckey>::iterator ite=keytable.begin();ite!=keytable.end();++ite)
				{	

					if((ite->second).keyflg)
					{
						
						if (DES_set_key_checked(&(ite->second.key), &ks) != 0)
						{
							 printf("convert to key_schedule failed.\n");
						}
						else
							DES_ncbc_encrypt((unsigned char *)crypline, (unsigned char*)(sendline+sizeof(mcheader)),8*((MCBUFFLEN-sizeof(mcheader))/8), &ks, &ivec, DES_ENCRYPT);
						sendto(sockfd, sendline, MCBUFFLEN, 0, pservaddr, sizeof(sockaddr_in));
					}
				}
				pthread_mutex_unlock(&mtx);//unlock
			}
			
           
      }
} 
void  chat_server(int sockfd,int sendfd, const SA *servaddr)//core function for receive thread
{
	bool frflg=false;
	std::map <in_addr_t,struct mckey>::iterator ite;
	int ret,fd,frlen;
	DES_key_schedule key_schedule;
	unsigned char keystr[16];
	DH *repdh;
	BIGNUM *pub_key=BN_new();
	unsigned short bnlen;
	int n;
	mcheader *hdr;
	char *msg;
	socklen_t socklen;
	char buf[MCBUFFLEN],sendline[MCBUFFLEN];
	char recvip[16];
	char *decryline=(char*)malloc((MCBUFFLEN-sizeof(mcheader))*sizeof(char));
	struct sockaddr_in cliaddr;
	bind(sockfd, servaddr,sizeof(sockaddr_in));
	mcast_join(sockfd, servaddr, sizeof(sockaddr_in), IF_NAME,IF_INDEX);//join the multicast group
	mcast_set_loop(sockfd, 0);
	while(1)
	{
		
		bzero(buf,MCBUFFLEN);
		bzero(decryline,MCBUFFLEN-sizeof(mcheader));
		n=recvfrom(sockfd, buf, MCBUFFLEN, 0,(SA *) &cliaddr, &socklen);
		hdr=(mcheader *)buf;
		msg=buf+sizeof(mcheader);
		inet_ntop(AF_INET,&(cliaddr.sin_addr),recvip,16);
		if(strcmp(recvip,selfip)==0||strcmp(recvip,"0.0.0.0")==0)
			{
				continue;
			}
		//printf("mtype: %d\n",hdr->mtype);
		//printf("mlen: %d\n",hdr->mlen);
		switch(hdr->mtype)
		{
			case MSG_TYPE_EXIT://receive a quit message, delete the corresponding entry of key table
				pthread_mutex_lock(&mtx);//lock
				keytable.erase(cliaddr.sin_addr.s_addr);
				pthread_mutex_unlock(&mtx);//unlock
				//printf("map size: %d\n",keytable.size());
				break;
			case MSG_TYPE_DHREQ://receive a key exchange message
				repdh=DH_new();
				repdh->g=BN_dup(reqdh->g);
				repdh->p=BN_new();
				memmove(&bnlen,msg,sizeof(unsigned short));
				BN_bin2bn((const unsigned char *)(msg+sizeof(unsigned short)),bnlen,repdh->p);
				memmove(&bnlen,buf+DHREQ_MID,sizeof(unsigned short));
				BN_bin2bn((const unsigned char *)(buf+DHREQ_MID+sizeof(unsigned short)),bnlen,pub_key);
				ret=DH_generate_key(repdh);
				if(ret!=1)
				{;}
				bnlen=DH_compute_key(keystr,pub_key,repdh);//generate key from request
				keystr[bnlen]=0;
				pthread_mutex_lock(&mtx);//lock
				DES_string_to_key((const char*)keystr, &(keytable[cliaddr.sin_addr.s_addr].key));//update the key table 
				keytable[cliaddr.sin_addr.s_addr].keyflg=false;
				pthread_mutex_unlock(&mtx);//unlock
				printf("%s has shared key with you, you can enable it by :e <ip address> or e: all\n",recvip);
				bzero(sendline,MCBUFFLEN);//generate reply message and send
				hdr=(mcheader*)sendline;
				hdr->mtype=MSG_TYPE_DHREP;
				hdr->mlen=MCBUFFLEN;
				memmove(sendline+sizeof(mcheader),recvip,strlen(recvip));
				bnlen=BN_bn2bin(repdh->pub_key,(unsigned char*)(sendline+DHREQ_MID+sizeof(unsigned short)));
				memmove(sendline+DHREQ_MID,&bnlen,sizeof(unsigned short));
				sendto(sendfd, sendline, MCBUFFLEN, 0, servaddr, sizeof(sockaddr_in));
				DH_free(repdh);
				break;
			case MSG_TYPE_DHREP:
				if(strcmp(msg,selfip)==0)//the reply should correspond to our request
				{	
					memmove(&bnlen,buf+DHREQ_MID,sizeof(unsigned short));
					BN_bin2bn((const unsigned char *)(buf+DHREQ_MID+sizeof(unsigned short)),bnlen,pub_key);
					bnlen=DH_compute_key(keystr,pub_key,reqdh);
					keystr[bnlen]=0;
					pthread_mutex_lock(&mtx);//lock
					DES_string_to_key((const char*)keystr, &(keytable[cliaddr.sin_addr.s_addr].key));
					keytable[cliaddr.sin_addr.s_addr].keyflg=false;//needs modify
					pthread_mutex_unlock(&mtx);//unlock
					printf("%s has shared key with you, you can enable it by :e <ip address> or :e all\n",recvip);
				}
				break;
			case MSG_TYPE_MSG://normal message
				if(decryandveri(msg,decryline,cliaddr.sin_addr.s_addr))
					printf("From %s: %s\n", recvip, decryline+VERI_CODE_LEN);
				break;
			case MSG_TYPE_FNAME://receive a file name
				ftflag=false;
				if(decryandveri(msg,decryline,cliaddr.sin_addr.s_addr))
				{
					fd = open(decryline+VERI_CODE_LEN, O_CREAT | O_EXCL | O_WRONLY, S_IROTH); 
					if(-1 == fd)
					{
						printf("open file error\n");
					}
					else
						frflg=true;
				}
				break;
			case MSG_TYPE_FCONT://content of file
				ftflag=false;
				if(decryandveri(msg,decryline,cliaddr.sin_addr.s_addr))
				{
					if(fd!=-1&&frflg)
					{
						if(write(fd, decryline+VERI_CODE_LEN, hdr->mlen)==-1)
						{
						printf("write file error\n");
						} 
					}
				}
				break;
			case MSG_TYPE_FTAIL://file's tail
				ftflag=true;
				if(decryandveri(msg,decryline,cliaddr.sin_addr.s_addr))
				{
					if(fd!=-1&&frflg)
					{
						if(write(fd, decryline+VERI_CODE_LEN, hdr->mlen)==-1)
						{
							printf("write file error\n");
						} 
						close(fd);
						printf("you have received a file\n");
						frflg=false;
					}
				}
				break;
			default:
				break;
				
				
				
		}
		
	}
}
void  *clithr(void *args)//thread entry point
{
	//cliParam prams=*(cliParam*)args;
	//dg_cli(prams.f, prams.sockfd, prams.saddr);
	dg_cli(((cliParam*)args)->f, ((cliParam*)args)->sockfd, ((cliParam*)args)->saddr);
}
void  *servthr(void *args)//thread entry point
{
	chat_server(((servParam*)args)->sockfd, ((servParam*)args)->sendfd,((servParam*)args)->saddr);
}
void getselfIP(char *ipBuf)//get ip of the interface in LAN
{
    FILE *mcfstream=NULL;    
    char buff[64];  
    memset(buff,0,sizeof(buff));
    std::string cmdstr1="ifconfig ";
    std::string cmdstr2=IF_NAME;
    std::string cmdstr3=" | grep \"inet addr:\" | awk \'{print $2}\' | cut -c 6-";  
    std::string cmdstr= cmdstr1+cmdstr2+cmdstr3;
    if(NULL==(mcfstream=popen(cmdstr.c_str(),"r")))    
    {   
        
        snprintf(ipBuf, 16, "%s","0.0.0.0");  
		err_quit("execute command fail"); 
    }       
    printf("%s\n",buff);
    if(NULL!=fgets(buff, sizeof(buff), mcfstream))   
    {   
        
        snprintf(ipBuf, 16, "%s",buff);  
    }   
    else  
    {  
        snprintf(ipBuf, 16, "%s","0.0.0.0");  
        pclose(mcfstream);   
    }  
    pclose(mcfstream);  
}
void dhreq(char *sendline)//transform the DH data structure to string and write them into send buffer
{
	int bnlen;
	bnlen=BN_bn2bin(reqdh->p,(unsigned char*)(sendline+sizeof(struct mcheader)+sizeof(unsigned short)));
    memmove(sendline+sizeof(struct mcheader),&bnlen,sizeof(unsigned short));
    bnlen=BN_bn2bin(reqdh->pub_key,(unsigned char*)(sendline+DHREQ_MID+sizeof(unsigned short)));
    memmove(sendline+DHREQ_MID,&bnlen,sizeof(unsigned short));
    
}
void genDHobj(DH *dh)//initialize the DH object
{
	int ret,i;
	
	ret=DH_generate_parameters_ex(dh,64,DH_GENERATOR_2,NULL);   
    if(ret!=1) {               //prime_len，generator is 2
        err_quit("DH_generate_parameters_ex err!");
    }
    ret=DH_check(dh,&i);
    if(ret!=1) {
        err_quit("DH_check err!");
    if(i&DH_CHECK_P_NOT_PRIME)
        err_quit("p value is not prime");
    if(i&DH_CHECK_P_NOT_SAFE_PRIME)
        err_quit("p value is not a safe prime");
    if (i&DH_UNABLE_TO_CHECK_GENERATOR)
        err_quit("unable to check the generator value");
    if (i&DH_NOT_SUITABLE_GENERATOR)
        err_quit("the g value is not a generator");
    }
    ret=DH_generate_key(dh);
    if(ret!=1) {
        err_quit("DH_generate_key err!");
    }
    ret=DH_check_pub_key(dh,dh->pub_key,&i);
    if(ret!=1) {
        if (i&DH_CHECK_PUBKEY_TOO_SMALL)
            err_quit("pub key too small");
        if (i&DH_CHECK_PUBKEY_TOO_LARGE)
            err_quit("pub key too large");
    }
}
void sighandler(int signum)//handle the ctrl+c command
{
	if(signum==SIGINT)
	{
		if(exitflag&&ftflag)
			exit(0);
		else
		{
			if(!exitflag)
				printf("\nPlease input \":q\" first, then input ctrl+c\n");
			if(!ftflag)
				printf("there is a file being transferred now in the channel, please wait.\n");
		}
	}
}
void vericodeinsert(char *line)//insert the "abcd" befor encryption
{
	for(int i=0;i<VERI_CODE_LEN;i++)
		line[i]='a'+i;
	
}
bool decryandveri(char *crypl,char *decryl,in_addr_t saddr)//decryption and check "abcd"
{
	DES_key_schedule ks;
	pthread_mutex_lock(&mtx);//lock
	if(keytable.find(saddr)!=keytable.end())
	{
		
		if (DES_set_key_checked(&(keytable[saddr].key), &ks) != 0)
		{
			pthread_mutex_unlock(&mtx);//unlock
			return false;
		}
		DES_ncbc_encrypt((unsigned char*)crypl, (unsigned char *)decryl, 8*((MCBUFFLEN-sizeof(mcheader))/8), &ks, &ivec, DES_DECRYPT);
		pthread_mutex_unlock(&mtx);//unlock
		for(int i=0;i<VERI_CODE_LEN;i++)
		{
			if(decryl[i]!=('a'+i))
				return false;
		}
		return true;
		
	}
	else
		pthread_mutex_unlock(&mtx);//unlock
		return false;
}
void displaykeytable()//display key table
{
	struct in_addr adr;
	char disip[16];
	pthread_mutex_lock(&mtx);
	if(!keytable.empty())
	{
		for(std::map <in_addr_t,struct mckey>::iterator ite=keytable.begin();ite!=keytable.end();++ite)
		{
			adr.s_addr=ite->first;
			inet_ntop(AF_INET,&adr,disip,16);
			printf("ip: %s; state: ",disip);
			if(ite->second.keyflg)
				{
					pthread_mutex_unlock(&mtx);
					printf("enabled\n");
				}
			else{
				pthread_mutex_unlock(&mtx);
				printf("disabled\n");
			}
		}
	}
	else
	{
		pthread_mutex_unlock(&mtx);
		printf("keytable is empty.Please use \':k\' \n");
	}
	
}
void outputhelp()//display help message
{
	printf("\n\nInput message directly for the message communication\nCommands:\n:%c         ...to exchange keys with others\n",CMD_TYPE_KEYSYC);
	printf(":%c all | <ip address>      ...to enable key\n:%c all | <ip address>       ...to disable key\n",CMD_TYPE_ENABLE,CMD_TYPE_DISABLE);
	printf(":%c <filename>     ...to transmit the file\n",CMD_TYPE_FILE);
	printf(":%c          ...to list the states of keys\n\n\n",CMD_TYPE_LIST);
}
