#include "globals.h"

int maintain_connection(int conn){
    char buf[MAX_BUFFER_SIZE];
    int close_conn = 0;
    while(close_conn==0){
        bzero(buf,MAX_BUFFER_SIZE);

        int num_byte_received = read(conn,buf,sizeof(buf));
        printf("received %d byte value : %s\n", num_byte_received,buf);

        if(strcmp(buf,"stop")==0 || num_byte_received==0)
            close_conn=1;

        bzero(buf,MAX_BUFFER_SIZE);
        snprintf(buf,MAX_BUFFER_SIZE,"%d",num_byte_received);
        // sleep(1);
        write(conn,buf,sizeof(buf));
        printf("sent : %s\n",buf);
    }
    close(conn);
}


int establish_connection(uint16_t port){
    int sock;
    struct sockaddr_in server; 
     sock=  socket(AF_INET,SOCK_STREAM,0);
    if(sock==-1){
        perror("SOCKET CREATION FAILED SERVER");
        exit(1);
    }

    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port= htons(port);

    if(bind(sock,(struct sockaddr*)&server,sizeof(server))!=0){
        perror("BIND STAGE");
        exit(0);
    }
    return sock;
}

int main(int argc, char ** argv){
    int server_sock;

    int conn,len;
    struct sockaddr_in client;
    server_sock = establish_connection(PORT);
    int max =10;
    while (max){
        max--;
        if(listen(server_sock,max)!=0){
           perror("LISTEN STAGE");
            exit(0);
        }

        conn = accept(server_sock,(struct sockaddr*)&client,&len);
        if(conn <0){
            perror("ACCEPT STAGE");
            exit(0);
        }
        maintain_connection(conn);
        close(conn);
    }

    close(server_sock);
    return 0;
}