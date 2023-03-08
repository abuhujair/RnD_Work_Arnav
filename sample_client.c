#include "globals.h"
#include "sample_headers.c"
#include <time.h>

void send_data(int sock){

    char buf[MAX_BUFFER_SIZE];
    // const char *strings [6] = {"name","my","name","is","DaVinci","stop"};
    // for(int i=0;i<6;i++){
    //     bzero(buf,MAX_BUFFER_SIZE);
    //     strcpy(buf,strings[i]);
    //     write(sock,buf,strlen(buf));
    //     printf("sent : %s\n",buf);
    //     bzero(buf,MAX_BUFFER_SIZE);
    //     read(sock,buf,sizeof(buf));
    //     printf("received : %s\n",buf);
    // }
    int test_count =10;
    time_t t;
    srand((unsigned) time(&t));   
    int ok_count=0;
    int nf_count=0; 
    for(int i=0;i<test_count;i++){
        int itr= rand()%h_count;
        if(itr==1)
            ok_count++;
        else if(itr==2)
            nf_count++;

        bzero(buf,MAX_BUFFER_SIZE);
        strcpy(buf,headers[itr]);
        write(sock,buf,strlen(buf));
        printf("sent : %s\n",buf);
        bzero(buf,MAX_BUFFER_SIZE);
        read(sock,buf,sizeof(buf));
        // printf("received : %s\n",buf);
    }

    printf("Total OK :%d \nTotal Not Found:%d\n",ok_count,nf_count);

    const char * str1 = "stop";
    bzero(buf,MAX_BUFFER_SIZE);
    strcpy(buf,str1);
    write(sock,buf,strlen(buf));
    // printf("sent : %s\n",buf);
    bzero(buf,MAX_BUFFER_SIZE);
    read(sock,buf,sizeof(buf));
    // printf("received : %s\n",buf);
}   

void establish_connection(uint16_t port , int * server_sock){
    int sock,conn,len;
    struct sockaddr_in server , client;
    sock=  socket(AF_INET,SOCK_STREAM,0);
    if(sock==-1){
        perror("SOCKET CREATION STAGE CLIENT");
        exit(1);
    }
    *server_sock = sock;

    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("192.168.0.105");
    server.sin_port= htons(port);
    if(connect(sock,(struct sockaddr*)&server,sizeof(server))!=0){
        perror("CONNECT STAGE");
        exit(0);
    }
}

int main(int argc,char ** argv){
    int server_sock;
    establish_connection(PORT,&server_sock);
    send_data(server_sock);
    close(server_sock);
    return 0;
}