#include <dos.h>
#include <stdio.h>
#include <string.h>
#include<stdlib.h>

union REGS a,b;
struct SREGS s;
unsigned char *pkt,macad[6];
int class,type,number,handle,mode,rec_pkt_len;
unsigned short bp,di,si,ds,es,dx,cx,bx,ax,ip,cs,flag;

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

arptable arp;

void print_mac_ad(const unsigned char buf[], int s){
	printf("%x:%x:%x:%x:%x:%x\n",buf[s],buf[s+1],buf[s+2],buf[s+3],buf[s+4],buf[s+5]);
}

int my_packet(unsigned char buf[]){
	int i;
	for(i = 0; i < 6; i++){
		if(buf[i] != macad[i]){
			return 0;
		}
	}
	return 1;
/*	if (buf[12] == 0x59 && buf[13] == 0xAF){
		return 1;
	}
	return 0;  */
}

void interrupt receiver(bp, di, si, ds, es, dx, cx, bx, ax, ip, cs, flags){
	int k;
	if ( ax == 0){
		pkt = (unsigned char *)malloc(sizeof(unsigned char)*cx);
		es=FP_SEG(pkt);
		di=FP_OFF(pkt);
		rec_pkt_len=cx;
        }
	if( ax==1 && my_packet(pkt)){
	       printf("Destination macid : ");
	       print_mac_ad(pkt,0);
	       printf("Source macid : ");
	       print_mac_ad(pkt,6);
	       printf("Type : %x%x\n", pkt[12],pkt[13]);
	       printf("Destination iip : %x.%x\n",pkt[14],pkt[15]);
	       printf("Source iip : %x.%x\n",pkt[16],pkt[17]);
	       for(k= 18; k < rec_pkt_len && pkt[k]!='\0'; k++)
			putch(pkt[k]);
		printf("\n");
	       free(pkt);
        }
}

int driver_info(){
	a.h.ah = 1;
	a.h.al = 255;
	int86x(0x60, &a, &b, &s);
	printf("Driver info %d class=%x type=%x number=%x\n",b.x.cflag,b.h.ch,b.x.dx,b.h.cl);
	if(!b.x.cflag){
		class = b.h.ch;
		type = b.x.dx;
		number = b.h.cl;
	}
	return b.x.cflag;
}

int get_address(){
        a.h.ah = 6;
        a.x.cx = 6;
	s.es = FP_SEG(macad);
	a.x.di = FP_OFF(macad);
	int86x(0x60,&a,&b,&s);
	printf("Ethernet Address ");
	print_mac_ad(macad,0);
	return b.x.cflag;
}

int access_type(){
	unsigned char c[2];
	a.h.ah = 2;
	a.h.al = class;
	a.x.bx = type;
	a.h.dl = number;
        a.x.cx = 0;
	s.es=FP_SEG(receiver);
	a.x.di=FP_OFF(receiver);
        c[0]=0xff;
        c[1]=0xff;
        s.ds=FP_SEG(c);
        a.x.si=FP_OFF(c);
	int86x(0x60,&a,&b,&s);
	printf("Access type : %d\n",b.x.cflag);
	if(!b.x.cflag){
		handle = b.x.ax;
		printf("Handle %x\n",b.x.ax);
	}
	return b.x.cflag;
}

int get_rcv_mode(){
        a.h.ah = 21;
        a.x.bx = handle;
	int86x(0x60,&a,&b,&s);
	if(!b.x.cflag){
		mode = b.x.ax;
		printf("Recieve Mode %x\n",b.x.ax);
	}
	return b.x.cflag;
}

int set_rcv_mode(int m){
        a.h.ah = 20;
        a.x.bx = handle;
	a.x.cx = m;
	int86x(0x60,&a,&b,&s);
	return b.x.cflag;
}

int send_pkt(const unsigned char buffer[],int length){
	int i;
	printf("Packet details\nDestination mac : ");
	print_mac_ad(buffer,0);
	printf("Source mac : ");
	print_mac_ad(buffer,6);
	printf("Destination iip : %x.%x\n",buffer[14],buffer[15]);
	printf("Source iip : %x.%x\n",buffer[16],buffer[17]);
	for(i=18; buffer[i] != '\0'; i++){
		putch(buffer[i]);
	}
	printf("\n");
	printf("Sending packet to ");
	print_mac_ad(buffer, 0);
	a.h.ah = 4;
        s.ds = FP_SEG(buffer);
        a.x.si = FP_OFF(buffer);
        a.x.cx = length;
	int86x(0x60,&a,&b,&s);
	return b.x.cflag;
}

int release_type(){
        a.h.ah=3;
        a.x.bx=handle;
	int86x(0x60,&a,&b,&s);
	if(!b.x.cflag){
		printf("Invaliding Handle\n");
	}
	return b.x.cflag;
}

int terminate(){
	a.h.ah = 5;
	a.x.bx = handle;
	int86x(0x60,&a,&b,&s);
	if(!b.x.cflag){
		printf("Terminated!\n");
	}
	return b.x.cflag;
}

void send_line(){
	char c;
	int x,y;
	int k, cnt = 0;
        unsigned char buf[60];
/*	buf[0] = 0x08;
	buf[1] = 0x00;
	buf[2] = 0x27;
	buf[3] = 0x93;
	buf[4] = 0xd6;
	buf[5] = 0x34;*/
        for(k = 6; k < 12; k++){
		buf[k] = macad[k-6];
        }
	buf[12] = 0xAB; buf[13] = 0xcd;
/*	buf[14] = 0x02; buf[15] = 0x01; */
	buf[16] = 0x02; buf[17] = 0x01;
/*	printf("Insert iip whom to send : ");
	scanf("%x.%x\n",buf[14],buf[15]);
	getch(); */
	while(1){
		printf("Insert iip whom to send : ");
		cscanf("%d.%d",&x,&y);
		getch();
		buf[14] = (unsigned char) ('\0'+x);
		buf[15] = (unsigned char) ('\0'+y);
/*	if (add_mac(buf, buf[14],buf[15]))
	while(1){*/
		k = 18;
		printf("\nMessage : ");
                do{
			c = getch();
			if(c== 27){
                                release_type();
				terminate();
				exit(0);
                        }
                        buf[k] = c;
			printf("%c",c);
                        k++;
		}while(c!=13);
                for ( ; k < 60; k++){
                        buf[k] = '\0';
		}
		if(add_mac(buf,buf[14],buf[15]))
			send_pkt(buf, 60);
	}

}

int add_mac(unsigned char buf[], unsigned char netid, unsigned char hostid){
	int table_offset = hostid - '\0';
	int i;
	if(netid != arp.netid){
		table_offset = 0;
	}else if(arp.table_cnt < table_offset)
		printf("ARP not resolved! IIP not exists\n");

	for(i = 0; i < 6; i++)
		buf[i] = arp.mactable[table_offset].mac[i];
	return (table_offset == 0);
}

main(){
	if(!driver_info() && !get_address() && !access_type() && !set_rcv_mode(3)){
		arp.vec = 0x60;
		arp.netid = 0x02;
		arp.mactable[0].iip[0] = 0x02;
		arp.mactable[0].iip[1] = 0x00;
		arp.mactable[0].mac[0] = 0x08;
		arp.mactable[0].mac[1] = 0x00;
		arp.mactable[0].mac[2] = 0x27;
		arp.mactable[0].mac[3] = 0x9e;
		arp.mactable[0].mac[4] = 0xaa;
		arp.mactable[0].mac[5] = 0x71;
		arp.table_cnt = 0;
		send_line();
	}
	else
		printf("Set up error!\n");
}