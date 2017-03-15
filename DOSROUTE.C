#include<dos.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

unsigned char vec_str[]={0x62,0x61,'\0'};
unsigned char intrr = 0x61;

union REGS a,b;
struct SREGS s;
unsigned char *pkt,macad[2][6];
int class,type,number,handle,mode,rec_pkt_len,adapter_cnt;
unsigned short bp,di,si,ds,es,dx,cx,bx,ax,ip,cs,flag;
unsigned char n;

typedef struct iipvsmac{
	unsigned char iip[2];
	unsigned char mac[6];
}iipvsmac;

typedef struct arptable{
	unsigned char vec;
	unsigned char netid;
	int table_cnt;
	iipvsmac mactable[10];
}arptable;

arptable arp[2];
unsigned char my_iip[2][2];

void print_mac_ad(const unsigned char buf[], int s){
	printf("%x:%x:%x:%x:%x:%x\n",buf[s],buf[s+1],buf[s+2],buf[s+3],buf[s+4],buf[s+5]);
}

int my_packet(unsigned char buf[]){
/*	return 1;
*/	int i,j;
	for (j=0 ; j < adapter_cnt; j++){
		for(i = 0; i < 6; i++){
			if(buf[i] != macad[j][i]){
				break;
			}
		}
		if(i == 6){
			return 1;
		}
	}
	return 0;
/*	if (buf[12] == 0xAB && buf[13] == 0xCD){
		return 1;
	}
	return 0;*/
}

int find_mac(unsigned char netid,unsigned char srcid, unsigned char *buf, unsigned char *vec){
	int i,j,k;
	for(i = 0; i < adapter_cnt; i++){
		if(netid == my_iip[i][0] && srcid == my_iip[i][1]){
			printf("Routers Packet!\n");
			return 0;
		}
	}
	for(i = 0; i < adapter_cnt; i++){
		if(arp[i].netid == netid){
			for(j = 0; j < arp[i].table_cnt; j++){
				if(arp[i].mactable[j].iip[1] == srcid){
					for(k = 0; k < 6; k++)
						buf[k] = arp[i].mactable[j].mac[k];
					*vec = arp[i].vec;
					return 1;
				}
			}
		}
	}
	printf("Address lookup failed! IIP does not exist\n");
	return 0;
}

void interrupt receiver(bp, di, si, ds, es, dx, cx, bx, ax, ip, cs, flags){
	int k;
	unsigned char ch,buf[6];
	if ( ax == 0){
		pkt = (unsigned char *)malloc(sizeof(unsigned char)*cx);
		es=FP_SEG(pkt);
		di=FP_OFF(pkt);
		rec_pkt_len=cx;
        }
	if( ax==1 && my_packet(pkt)){
               printf("Destination address : ");
	       print_mac_ad(pkt,0);
	       printf("Source adress : ");
	       print_mac_ad(pkt,6);
	       printf("Type : %x%x\n", pkt[12],pkt[13]);
	       printf("Destination iip : %x.%x\n",pkt[14],pkt[15]);
	       printf("Source iip : %x.%x\n",pkt[16],pkt[17]);
	       for(k = 18; k < rec_pkt_len && pkt[k] != '\0'; k++)
			putch(pkt[k]);
	       printf("\n");
	       if(find_mac(pkt[14],pkt[15],buf,&ch)){
			printf("Mapping found, iip : %x.%x  mac : %x.%x.%x.%x.%x.%x\n",pkt[14],pkt[15],buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);

		/*	for(k= 18; k < rec_pkt_len && pkt[k]!='\0'; k++)
				putch(pkt[k]);
			printf("\n");*/
			for(k = 0; k < 6; k++){
				pkt[k] = buf[k];
			}
			send_pkt(pkt,60,ch);
	       }
	       free(pkt);
        }
}

int driver_info(int adapter_no){
	a.h.ah = 1;
	a.h.al = 255;
	int86x(vec_str[adapter_no], &a, &b, &s);
/*	printf("Driver info %d class=%x type=%x number=%x\n",b.x.cflag,b.h.ch,b.x.dx,b.h.cl);
*/	if(!b.x.cflag){
		class = b.h.ch;
		type = b.x.dx;
		number = b.h.cl;
	}
	return b.x.cflag;
}

int get_address(int adapter_no){
        a.h.ah = 6;
	a.x.cx = 6;
	s.es = FP_SEG(macad[adapter_no]);
	a.x.di = FP_OFF(macad[adapter_no]);
	int86x(vec_str[adapter_no],&a,&b,&s);
	printf("Ethernet Address ");
	print_mac_ad(macad[adapter_no],0);
	return b.x.cflag;
}

int access_type(int adapter_no){
	unsigned char c[2];
	a.h.ah = 2;
	a.h.al = class;
	a.x.bx = type;
	a.h.dl = number;
	printf("class = %x type=%x number=%x\n",class,type,n);
	n += 1;
        a.x.cx = 0;
	s.es=FP_SEG(receiver);
	a.x.di=FP_OFF(receiver);
        c[0]=0xff;
        c[1]=0xff;
        s.ds=FP_SEG(c);
        a.x.si=FP_OFF(c);
	int86x(vec_str[adapter_no],&a,&b,&s);
	printf("Access type flag : %d\n",b.x.cflag);
	if(!b.x.cflag){
		handle = b.x.ax;
		printf("For %x Handle %x\n",vec_str[adapter_no],b.x.ax);
	}
	return b.x.cflag;
}

int send_pkt(const unsigned char buffer[],int length, unsigned char vec){
	int i;
/*	for(i=18; buffer[i] != '\0'; i++){
		putch(buffer[i]);
	}
	printf("\n");*/
	printf("Sending packet to ");
	print_mac_ad(buffer, 0);
/*	printf("Type : %x %x\n",buffer[12],buffer[13]);
	printf("At interrupt : %x\n",vec);*/
	a.h.ah = 4;
        s.ds = FP_SEG(buffer);
        a.x.si = FP_OFF(buffer);
        a.x.cx = length;
	int86x(vec,&a,&b,&s);
	printf("Send Flag %x\n",b.x.cflag);
	return b.x.cflag;
}

int release_type(int adapter_no){
        a.h.ah=3;
        a.x.bx=handle;
	int86x(vec_str[adapter_no],&a,&b,&s);
	if(!b.x.cflag){
		printf("Invaliding Handle\n");
	}
	return b.x.cflag;
}

int terminate(int adapter_no){
	a.h.ah = 5;
	a.x.bx = handle;
	int86x(vec_str[adapter_no],&a,&b,&s);
	if(!b.x.cflag){
		printf("Terminated!\n");
	}
	return b.x.cflag;
}

void send_line(){
        char c;
	int k, cnt = 0;
        unsigned char buf[60];
	buf[0] = 0x08;
	buf[1] = 0x00;
	buf[2] = 0x27;
	buf[3] = 0x2E;
	buf[4] = 0x11;
	buf[5] = 0x75;
        for(k = 6; k < 12; k++){
		buf[k] = macad[0][k-6];
        }
	buf[12] = 0xAB;buf[13] = 0xCD;
	while(1){
                k = 14;
                do{
			c = getch();
			if(c== 27){
				stop_router();
				exit(0);
                        }
                        buf[k] = c;
			printf("%c",c);
                        k++;
		}while(c!=13);
                for ( ; k < 60; k++){
                        buf[k] = '\0';
                }
		send_pkt(buf, 60, 0x62);
	}

}

int start_router(){
	int i;
	for(i = 0; vec_str[i]!='\0'; i++){
		if(!driver_info(i) && !get_address(i) && !access_type(i)){
			printf("Adapter is ready\n");
		}
		else{
			return 1;
		}
	}
	adapter_cnt = i;
	my_iip[0][0] = 0x01; my_iip[0][1] = 0x00;
	my_iip[1][0] = 0x02; my_iip[0][1] = 0x00;
	arp[0].vec = 0x62;
	arp[1].vec = 0x61;
	arp[0].netid = 0x01;
	arp[1].netid = 0x02;
	arp[0].table_cnt = 3;
	arp[1].table_cnt = 1;
	arp[0].mactable[0].iip[0] = 0x01;
	arp[0].mactable[0].iip[1] = 0x01;
	arp[0].mactable[0].mac[0] =  0x08;
	arp[0].mactable[0].mac[1] =  0x00;
	arp[0].mactable[0].mac[2] =  0x27;
	arp[0].mactable[0].mac[3] =  0x00;
	arp[0].mactable[0].mac[4] =  0x47;
	arp[0].mactable[0].mac[5] =  0xCD;
	arp[0].mactable[1].iip[0] = 0x01;
	arp[0].mactable[1].iip[1] = 0x02;
	arp[0].mactable[1].mac[0] = 0x08;
	arp[0].mactable[1].mac[1] = 0x00;
	arp[0].mactable[1].mac[2] = 0x27;
	arp[0].mactable[1].mac[3] = 0xBC;
	arp[0].mactable[1].mac[4] = 0x1C;
	arp[0].mactable[1].mac[5] = 0xD6;
	arp[0].mactable[2].iip[0] = 0x01;
	arp[0].mactable[2].iip[1] = 0x03;
	arp[0].mactable[2].mac[0] = 0x08;
	arp[0].mactable[2].mac[1] = 0x00;
	arp[0].mactable[2].mac[2] = 0x27;
	arp[0].mactable[2].mac[3] = 0x59;
	arp[0].mactable[2].mac[4] = 0xf6;
	arp[0].mactable[2].mac[5] = 0x8C;
	arp[1].mactable[0].iip[0] =  0x02;
	arp[1].mactable[0].iip[1] =  0x01;
	arp[1].mactable[0].mac[0] =  0x08;
	arp[1].mactable[0].mac[1] =  0x00;
	arp[1].mactable[0].mac[2] =  0x27;
	arp[1].mactable[0].mac[3] =  0x80;
	arp[1].mactable[0].mac[4] =  0x2D;
	arp[1].mactable[0].mac[5] =  0xCD;
	return 0;

}

int stop_router(){
	int i;
	for(i= 0; vec_str[i]!='\0'; i++){
		release_type(i);
		terminate(i);
	}
}

main(){
/*	intrr = 0x61;
	if(!driver_info() && !get_address() && !access_type() && !set_rcv_mode(3))
		send_line();
	else
		printf("Set up error!\n");
*/
	n = 0;
	start_router();
	send_line();
	stop_router();
}