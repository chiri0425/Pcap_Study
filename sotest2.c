#include<stdio.h>
#include<stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>


#define PORT 4000

int main() {

	int clientSocket = socket(PF_INET, SOCK_STREAM, 0);
	if(clientSocket == -1) {
		printf("Fail client socket!\n");
		return 0;
	}
	printf("Success client socket!\n");
	

	struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_addr.s_addr = inet_addr("100.212.22.128");
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(PORT);
	

	connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
	
	while(1){
	printf("Start baseball game\n");
	printf("Enter the three number(ex: 1 2 3)\n-->");
	int clientNumber[3];
	scanf("%d %d %d", &clientNumber[0], &clientNumber[1], &clientNumber[2]);
	int i;
	for(i=0;i<3;i++) {
		clientNumber[i] = htonl(clientNumber[i]);
	}
	
	write(clientSocket, (char *)clientNumber, sizeof(clientNumber));
		

		int score[2];
		read(clientSocket, (char *)score, sizeof(score));
		int strike = ntohl(score[0]);
		int ball = ntohl(score[1]);
		printf(": %d Strike  %d Ball\n\n", strike, ball);
		
		if(strike == 3) {
			printf("3 Strike. End the program\n\n");
			break;
		}		
	}	
	

	close(clientSocket);	
}
