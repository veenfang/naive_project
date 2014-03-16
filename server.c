#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 1024
#define PORT 8888

int main(){
    int socketHandler;
    struct sockaddr_in hostSocketInfo;
    socketHandler = socket(AF_INET, SOCK_DGRAM, 0);
    bzero(&hostSocketInfo, sizeof(struct sockaddr_in));
    hostSocketInfo.sin_family = AF_INET;
    hostSocketInfo.sin_addr.s_addr = htonl(INADDR_ANY);
    hostSocketInfo.sin_port = htons(PORT);
    if(bind(socketHandler, (struct sockaddr*)&hostSocketInfo, sizeof(struct sockaddr_in)) < 0){
        printf("bind error");
        exit(EXIT_FAILURE);
    }
    //--------
    int val=1;
    setsockopt(socketHandler, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    //--------
    struct sockaddr_in clientSocketInfo;
    int messageLength;
    int infoLength;
    char message[MAX_SIZE+1];
    while(1){
        messageLength = recvfrom(socketHandler, message, MAX_SIZE, 0, (struct sockaddr*)&clientSocketInfo, (socklen_t*)&infoLength);
        message[messageLength] = '\0';
        printf("%s", message);
    }

    return 0;
}
