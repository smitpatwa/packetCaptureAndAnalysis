#include <netinet/in.h>
#include <errno.h>
#include <stdio.h> //For standard things
#include <stdlib.h>    //malloc
#include <string.h>    //strlen
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h>  //For ETH_P_ALL
#include <net/ethernet.h>  //For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <stdbool.h>
#include <time.h>
#define MAXPACKETS 1024

void make_logfile(char* option);
void ProcessPacket(unsigned char* , int);
void printIpHeader(unsigned char* , int);
void printTcpPacket(unsigned char * , int );
void printUdpPacket(unsigned char * , int );
void printIcmpPacket(unsigned char* , int );
void printOtherPacket(unsigned char* , int ); //only print ethernet and ip headers for such packets
void PrintData (unsigned char* , int);
void preProcess();
void processAllPackets();
void filterPackets();
void saveMacAddrs();
void saveIpAddrs();
void plotTraffic();

struct PacketData{
	int data_size;
	unsigned char buffer[65536];
	double time_added;
};

struct PacketData packetList[MAXPACKETS];
int packet_ptr;
char ipList[MAXPACKETS][20];
int ip_ptr;
char macList[MAXPACKETS][20];
int mac_ptr;
int protocol_port[] = {80, 23};
char* protocol_name[] = {"HTTP", "FTP"};
int sz = sizeof(protocol_port)/sizeof(int);
int otherORnot;

FILE *logfile;
char logfilename[20];
struct sockaddr_in source,dest;
int tcp_cnt,udp_cnt,icmp_cnt,others_cnt,igmp_cnt,total_cnt,i,j;	
clock_t InitTime;

void addPacket(char* buf, int size)
{
	packetList[packet_ptr].data_size = size;
	int i;
	for(i=0; i<size; i++){
		packetList[packet_ptr].buffer[i] = buf[i];
	}
    packetList[packet_ptr].time_added = (double)(clock() - InitTime)*1000.0/CLOCKS_PER_SEC;
	packet_ptr+=1;
}

int get_sock_raw ()
{
    int sock_raw = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if (sock_raw < 1) {
        printf ("ERROR: Could not open socket. Please check permissions!\n");
        exit(1);
    }

    return sock_raw;
}

void make_logfile(char* option)
{
	logfile=fopen(logfilename, option);
	if(logfile==NULL) 
	{
		printf("Unable to create %s file.", logfilename);
	}
}
int main()
{
	int saddr_size , data_size;
	int max_capture;
	struct sockaddr saddr;

	unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

	//creating log file for packets
	printf("Please enter the name of log file (log.txt): ");
	scanf("%s", logfilename);
	make_logfile("w");

	printf("Starting the capture of packets...\n");
	
	int sock_raw = get_sock_raw();
	
	printf("Enter Number of packets to capture (MAX allowed %d): ", MAXPACKETS);
	scanf("%d", &max_capture);
	if(max_capture > MAXPACKETS){
		max_capture = MAXPACKETS;
	}
	InitTime = clock();  // Save the time when capturing started
	while(total_cnt < max_capture) {

		saddr_size = sizeof(saddr);
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
		if(data_size < 0) {
			printf("ERROR: Packet not received.\n");
			return 1;
		}
		printf("Packets Received : %d\r" , total_cnt++);
		//Now add the packet to the buffer 
		addPacket(buffer , data_size);
	}
	//Now process the packet to make usable structs for analysis
	preProcess();

	int choice;

	//loop runs till option 3 is entered for exiting
    while(choice!=4)
    {
    	fseek(logfile, 0, SEEK_SET);
    	printf("\nAnalysis of Packets (All the output will be printed to \"%s\" file)\n", logfilename);
    	printf("1. Print all captured packets\n");
    	printf("2. Filter packets\n");
    	printf("3. Display Network Traffic Graph\n");
    	printf("4. Exit\n");
    	printf("Enter your choice: ");
        scanf("%d",&choice);

        switch(choice){
        	case 1:
        		processAllPackets();
        		break;
        	case 2:
        		filterPackets(); 
        		break;
        	case 3:
        		plotTraffic();
        		break;
        	default:
        		break;
        }
    }

	close(sock_raw);
	return 0;
}

void preProcess()
{
	int i, j, ip_fl=0, fl=1;
	char tmp_strS[20], tmp_strD[20];
	for(i=0; i<packet_ptr; i++){
		struct ethhdr *eth = (struct ethhdr *)(packetList[i].buffer);
		sprintf(tmp_strS, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5] );
		sprintf(tmp_strD, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5] );
		
		//checking available mac addresses using source address of packet
		fl=1;
		for(j=0; j<mac_ptr; j++){
			if(!strcmp(macList[j], tmp_strS)){
				fl =0;
				break;
			}
		}
		if(fl){
			strcpy(macList[mac_ptr++],tmp_strS);
		}
		//checking available mac addresses using destination address of packet
		fl=1;
		for(j=0; j<mac_ptr; j++){
			if(!strcmp(macList[j], tmp_strD)){
				fl =0;
				break;
			}
		}
		if(fl){
			strcpy(macList[mac_ptr++],tmp_strD);
		}

		struct iphdr *iph = (struct iphdr *)(packetList[i].buffer  + sizeof(struct ethhdr) );
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

		strcpy(tmp_strS, inet_ntoa(source.sin_addr));
		strcpy(tmp_strD, inet_ntoa(dest.sin_addr));
		
		//checking available ip addresses using source ip address of packet
		fl=1;
		for(j=0; j<ip_ptr; j++){
			if(!strcmp(ipList[j], tmp_strS)){
				fl =0;
				break;
			}
		}
		if(fl){
			strcpy(ipList[ip_ptr++],tmp_strS);
		}
		//checking available ip addresses using destination ip address of packet		
		fl=1;
		for(j=0; j<ip_ptr; j++){
			if(!strcmp(ipList[j], tmp_strD)){
				fl =0;
				break;
			}
		}
		if(fl){
			strcpy(ipList[ip_ptr++],tmp_strD);
		}
	}
}
void processAllPackets()
{
	int i;
	tcp_cnt=udp_cnt=icmp_cnt=others_cnt=igmp_cnt=total_cnt = 0;
	logfile = freopen(logfilename, "w", logfile);
	for(i=0; i<packet_ptr; i++){
		ProcessPacket(packetList[i].buffer, packetList[i].data_size);
	}
	printf("\n");
	fflush(logfile);
	printf("All packets are printed to %s file\n", logfilename);
}

void filterPackets()
{
	int choice=0, i, j, choice2=0;
	char tmp_strS[20], tmp_strD[20];
	while(choice<1 || choice>5){
		printf("\n========Available Filters========\n");
		printf("1. Filter by MAC address\n");
		printf("2. Filter by IP\n");
		printf("3. Filter by Protocol\n");
		printf("4. Back to main menu\n");
		printf("Select an option: ");
		scanf("%d", &choice);
		printf("================================\n");
	}
	tcp_cnt=udp_cnt=icmp_cnt=others_cnt=igmp_cnt=total_cnt = 0;
	switch(choice){
		case 1:
			printf("\nList of MAC address:\n");
			for(i=0; i<mac_ptr; i++){
				printf("%d. %s\n", i+1, macList[i]);
			}
			printf("Select a MAC address from above list(enter number): ");
			scanf("%d", &choice2);
			choice2 -= 1;
			logfile = freopen(logfilename, "w", logfile);
			for(i=0; i<packet_ptr; i++){
				struct ethhdr *eth = (struct ethhdr *)(packetList[i].buffer);
				sprintf(tmp_strS, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5] );
				sprintf(tmp_strD, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5] );
				if(!strcmp(tmp_strS, macList[choice2]) || !strcmp(tmp_strD, macList[choice2])){
					ProcessPacket(packetList[i].buffer, packetList[i].data_size);
				}
			}
			fflush(logfile);
			printf("\n\nAll packets containing source or destination MAC address as %s are printed to %s file\n\n", macList[choice2], logfilename);
			break;
		case 2:
			printf("\nList of IP address:\n");
			for(i=0; i<ip_ptr; i++){
				printf("%d. %s\n", i+1, ipList[i]);
			}
			printf("Select a IP address from above list(enter number): ");
			scanf("%d", &choice2);
			choice2 -= 1;
			logfile = freopen(logfilename, "w", logfile);
			for(i=0; i<packet_ptr; i++){
				struct iphdr *iph = (struct iphdr *)(packetList[i].buffer  + sizeof(struct ethhdr) );
				memset(&source, 0, sizeof(source));
				source.sin_addr.s_addr = iph->saddr;
				memset(&dest, 0, sizeof(dest));
				dest.sin_addr.s_addr = iph->daddr;

				strcpy(tmp_strS, inet_ntoa(source.sin_addr));
				strcpy(tmp_strD, inet_ntoa(dest.sin_addr));
				
				if(!strcmp(tmp_strS, ipList[choice2]) || !strcmp(tmp_strD, ipList[choice2])){
					ProcessPacket(packetList[i].buffer, packetList[i].data_size);
				}
			}
			fflush(logfile);
			printf("\n\nAll packets containing source or destination IP address as %s are printed to %s file\n\n", ipList[choice2], logfilename);
			break;
		case 3:
			printf("\nList of Protocols:\n");
			for(i=0; i<sz; i++){
				printf("%d. %s (port: %d)\n", i+1, protocol_name[i], protocol_port[i]);
			}
			printf("Select a Protocol from above list(enter number): ");
			scanf("%d", &choice2);
			choice2 -= 1;
			logfile = freopen(logfilename, "w", logfile);
			int tmp_cnt=0;
			for(i=0; i<packet_ptr; i++){
				struct iphdr *iph = (struct iphdr *)(packetList[i].buffer  + sizeof(struct ethhdr) );
				if(iph->protocol != 6){
					continue;
				}
				unsigned short iphdrlen;				
				iphdrlen = iph->ihl*4;
				struct tcphdr *tcph=(struct tcphdr*)(packetList[i].buffer + iphdrlen + sizeof(struct ethhdr));
				if(ntohs(tcph->source)==protocol_port[choice2] || ntohs(tcph->dest) == protocol_port[choice2] ){
					tmp_cnt+=1;
					ProcessPacket(packetList[i].buffer, packetList[i].data_size);
				}
			}
			fflush(logfile);
			printf("\n\n%s packets on standard port (%d): \n\tTotal Captured: %d\n\tPrinted to %s file\n\n",protocol_name[choice2], protocol_port[choice2], tmp_cnt, logfilename);
			break;
		default:
			return;
			break;
	}
}

void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total_cnt;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp_cnt;
			printIcmpPacket( buffer , size);
			break;
		
		case 2:  //IGMP Protocol
			++igmp_cnt;
			break;
		
		case 6:  //TCP Protocol
			++tcp_cnt;
			printTcpPacket(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp_cnt;
			printUdpPacket(buffer , size);
			break;
		
		default: //Some Other Protocol
			++others_cnt;
			printOtherPacket(buffer,size);
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp_cnt , udp_cnt , icmp_cnt , igmp_cnt , others_cnt , total_cnt);
	fflush(stdout);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "=========Ethernet Header========\n");
	fprintf(logfile , "Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "Protocol            : %u \n",(unsigned short)eth->h_proto);
	fprintf(logfile,    "=================================" );
	fprintf(logfile , "\n");
}

void printIpHeader(unsigned char* Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);
 
	unsigned short iphdrlen;  	int fl=1;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;


	if(!fl) return; else{
	fprintf(logfile , "\n");
	fprintf(logfile , "==========IP Header=======\n");
	fprintf(logfile , "IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "Identification    : %d\n",ntohs(iph->id));
	fprintf(logfile , "TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "Destination IP   : %s\n",inet_ntoa(dest.sin_addr)); } if(!fl) return; 
	fprintf(logfile, "===========================");
	fprintf(logfile , "\n");	
}

void printTcpPacket(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	int fl=1;
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	fprintf(logfile , "\n\n==========================================================\n");
	fprintf(logfile , "***********************TCP Packet*************************\n");	
		
	printIpHeader(Buffer,Size);
	if(!fl) return; else{	
	fprintf(logfile , "\n");
	fprintf(logfile , "========TCP Header========\n");
	fprintf(logfile , "Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile , "Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logfile , "Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile , "Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile , "Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile , "Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile , "Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile , "Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile , "Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile , "Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile , "Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile, "===========================" );
	fprintf(logfile , "\n");	
		
	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
					
	fprintf(logfile , "\n\n***********************TCP Packet Ends*********************\n");
	fprintf(logfile ,     "==========================================================\n");} if(!fl) return; 
}

void printUdpPacket(unsigned char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;int fl=1;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	fprintf(logfile , "\n\n==========================================================\n");
	fprintf(logfile , 	  "************************UDP Packet*************************\n");	
		
	printIpHeader(Buffer,Size);			
	if(!fl) return; else{	
	fprintf(logfile , "\n========UDP Header=======\n");
	fprintf(logfile , "Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "UDP Checksum     : %d\n" , ntohs(udph->check));
	fprintf(logfile, "===========================");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "Data Payload\n");	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);

	fprintf(logfile , "\n\n***********************UDP Packet Ends*********************\n");
	fprintf(logfile ,     "==========================================================\n");} if(!fl) return;
}

void printIcmpPacket(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	fprintf(logfile , "\n\n==========================================================\n");
	fprintf(logfile ,     "***********************ICMP Packet*************************\n");	
	printIpHeader(Buffer , Size);
			
	fprintf(logfile , "\n");
		
	fprintf(logfile , "=============ICMP Header=============\n");
	fprintf(logfile , "Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile , "Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile , "Checksum : %d\n",ntohs(icmph->checksum));
	fprintf(logfile , "\n");
	fprintf(logfile, "===========================" );
	fprintf(logfile , "\n");		

	fprintf(logfile , "Data Payload\n");	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , (Size - header_size) );
	
	fprintf(logfile , "\n\n***********************ICMP Packet Ends*********************\n");
	fprintf(logfile ,     "==========================================================\n");
}

void printOtherPacket(unsigned char* Buffer, int Size)
{
	fprintf(logfile , "\n\n==========================================================\n");
	fprintf(logfile , "***********************Other Packet*************************\n");

	printIpHeader(Buffer,Size);
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	unsigned short iphdrlen = iph->ihl*4;
	int header_size =  sizeof(struct ethhdr) + iphdrlen; 

	fprintf(logfile , "Other Data\n");	
	PrintData(Buffer + header_size , Size - header_size );
	fprintf(logfile , "\n\n***********************Other Packet Ends*********************\n");
	fprintf(logfile ,     "==========================================================\n");
}

void PrintData (unsigned char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}

void plotTraffic()
{
    char * commands[] = {
    	"set grid"
    	,"set terminal png"
    	,"set output \'net_traffic.png\'"
    	,"set xlabel \'Time (in seconds)\'"
    	,"set ylabel \'Number of Packets\'"
    	,"set title \'Network Traffic\'"
    	,"set autoscale"
		,"plot \'net_traffic.txt\' using 1:2 with lines title \'traffic\'"
		,"replot"
	};
    
    FILE * data_file = fopen("net_traffic.txt", "w");
    
    int i,j;
    int MAXTIME = (int) (packetList[packet_ptr -1].time_added+1);
    int num_freq[MAXTIME];
    memset(num_freq, 0, sizeof(num_freq));
    
    for (i=0; i<packet_ptr; i++) {
        j = (int)(packetList[i].time_added);
        num_freq[j]++;
    }
    j = 0;
    for(i=0 ; i<MAXTIME; i++) {
        fprintf(data_file, "%d %d\n", j, num_freq[i]);
        j += 1;
    }

    fclose(data_file);

    FILE * gnuplotPipe = popen ("gnuplot -persistent", "w");
    for (i=0; i<9; i++){
       fprintf(gnuplotPipe, "%s \n", commands[i]); 
    }
    fclose(gnuplotPipe);

    system("eog net_traffic.png >/dev/null 2>&1");
}