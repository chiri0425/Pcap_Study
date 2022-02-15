#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>


#define PORT 4000

//void error_handling(char *message);

/* tcp server main */
int main(){

   int server_socket;
   int client_socket;
   int client_addr_size;

   struct sockaddr_in server_addr;
   struct sockaddr_in client_addr;

   server_socket  = socket( PF_INET, SOCK_STREAM, 0);
   if(server_socket == -1){
      printf( "server socket creation failed.\n");
      exit(1);
   }
  
   memset( &server_addr, 0, sizeof( server_addr));
   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(PORT);
   server_addr.sin_addr.s_addr= htonl( INADDR_ANY);

   if (bind( server_socket, (struct sockaddr*)&server_addr,
               sizeof(server_addr)) == -1){
      printf( "bind error\n");
      exit( 1);
   }
   if(listen(server_socket, 5) == -1){
      printf( "listen error\n");
      exit( 1);
   }
   printf("waiting....the other person...\n");

     client_addr_size=sizeof( client_addr);
      client_socket=accept( server_socket, NULL, NULL);
      if (client_socket == -1){
         printf( "accept error\n");
         exit( 1);
      }
     printf("The other person has logged in\n");
     printf("Start baseball game!\n");

    
     int serverNumber[3];
     srand((unsigned)time(NULL));
	
	do {
		serverNumber[0] = rand() %10;
		serverNumber[1] = rand() %10;
		serverNumber[2] = rand() %10;
	}
	while( (serverNumber[0]==serverNumber[1]) | (serverNumber[1]==serverNumber[2]) | (serverNumber[2]==serverNumber[0]));
	printf("servernum --> %d %d %d\n", serverNumber[0], serverNumber[1], serverNumber[2]);
	

	int fromClientNumber[3];
	int toClientScore[2];

	while(1){
	read(client_socket, (char*)fromClientNumber, sizeof(fromClientNumber));
	int i;
        for(i=0;i<3;i++) {
		fromClientNumber[i]=ntohl(fromClientNumber[i]);
	}
	printf("clientnum --> %d %d %d\n", fromClientNumber[0], fromClientNumber[1], fromClientNumber[2]);
	
	int j;
	int strike=0;
	int ball=0;
	for(j=0;j<3;j++){
	int tmpserver = serverNumber[j];
	int k;
		for(k=0;k<3;k++){
		  int tmpclient = fromClientNumber[k];
		  if(tmpserver==tmpclient){
  			if(j==k) strike++;
			else ball++;
	}

     }
	}

		printf("%d Strike  %d Ball\n\n", strike, ball);
		

		toClientScore[0] = htonl(strike);
		toClientScore[1] = htonl(ball);
		write(client_socket, (char*)toClientScore,sizeof(toClientScore));
		
		if(strike == 3) {
			printf("3 Strike. End the Program\n");
			break;
		}
	}


//      close(server_socket);
      close(client_socket);
    
    
  }	

