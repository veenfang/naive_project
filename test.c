#include "sniffer.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <math.h>

#define MAX_SIGNAL_COUNT 200
#define MAX_DEVICE_COUNT 200
#define MAX_SEND_SIZE 1024
#define SERVER_PORT 8888
#define SERVER_IP "127.0.0.1"

struct DeviceInfoDef{
  long   time;
  char   srcMac[20];
  char   apMac[20];
  double signalSum;
  int    signalCount;
  double variance;
  double mean;
  int    signalSingle[MAX_SIGNAL_COUNT];
};

typedef struct DeviceInfoDef DeviceInfo;

void initDeviceInfo(DeviceInfo *deviceInfo);
void catchPacket(DeviceInfo *deviceInfo, int *deviceCount);
void handleSignal(DeviceInfo *deviceInfo, char *mac, int signal, int *deviceCount);
int  search(DeviceInfo *deviceInfo, char *mac, int *deviceCount);
void modify(DeviceInfo *deviceInfo, int signal, int pos);
void sendInfo(DeviceInfo *deviceInfo, int *deviceCount, char *message);
double computeVariance(int *numberList, int count, int mean);
void *threadToGetPacket(void *ptr);
void *threadToSendInfo(void *ptr);

int _socketHandler;
struct sockaddr_in _clientInfo;
char _message[MAX_SEND_SIZE];
DeviceInfo _deviceInfo[MAX_DEVICE_COUNT];
int _deviceCount;
pthread_mutex_t mutex;

int main(){
  _socketHandler = socket(AF_INET, SOCK_DGRAM, 0);
  bzero(&_clientInfo, sizeof(struct sockaddr_in));
  _clientInfo.sin_family = AF_INET;
  _clientInfo.sin_port = htons(SERVER_PORT);
  if(inet_aton(SERVER_IP, &_clientInfo.sin_addr) < 0){
    printf("error");
    exit(EXIT_FAILURE);
  }
  initDeviceInfo(_deviceInfo);
  
  //-------------------------------
  pthread_mutex_init(&mutex, NULL);
  pthread_t idToGetPacket;
  pthread_t idToSendInfo;
  pthread_create(&idToGetPacket, NULL, threadToGetPacket, NULL);
  pthread_create(&idToSendInfo, NULL, threadToSendInfo, NULL);

  pthread_join(idToGetPacket, NULL);
  pthread_join(idToSendInfo, NULL);
  //-------------------------------
  return 0;
}

void *threadToGetPacket(void *ptr){
  catchPacket(_deviceInfo, &_deviceCount);
}

void *threadToSendInfo(void *ptr){
  sendInfo(_deviceInfo, &_deviceCount, _message);
}

void initDeviceInfo(DeviceInfo *deviceInfo){
  int i;
  for(i = 0; i < MAX_DEVICE_COUNT; i++){
    deviceInfo[i].signalSum = 0;
    deviceInfo[i].signalCount = 0;
    sprintf(deviceInfo[i].apMac, "20-7C-8F-6A-66-9B");  //todo: get MAC automatically
  }
}

void sendInfo(DeviceInfo *deviceInfo, int *deviceCount, char *message){
  while(1){
    sleep(2);
    pthread_mutex_lock(&mutex);
    int i = 0;
    for(i = 0; i < *deviceCount; i++){
      time_t rawtime;
      time(&rawtime);
      deviceInfo[i].time = (long)rawtime;
      deviceInfo[i].mean = (deviceInfo[i].signalSum)/(deviceInfo[i].signalCount);
      deviceInfo[i].variance = computeVariance(deviceInfo[i].signalSingle, deviceInfo[i].signalCount, deviceInfo[i].mean);
      sprintf(message, "%ld|%s|%s|%f|%f|%d\n", deviceInfo[i].time, deviceInfo[i].srcMac, deviceInfo[i].apMac,
              deviceInfo[i].mean, deviceInfo[i].variance, deviceInfo[i].signalCount);
      printf("%s", message);
      sendto(_socketHandler, message, strlen(message)+1, 0, (struct sockaddr*)&_clientInfo, sizeof(struct sockaddr_in));
      deviceInfo[i].signalCount = 0;
      deviceInfo[i].signalSum = 0;
    }
    *deviceCount = 0;
    pthread_mutex_unlock(&mutex);
  } 
}

double computeVariance(int *numberList, int count, int mean){
  double result = 0, temp;
  int i;
  for(i = 0; i < count; i++){
    temp = numberList[i] - mean;
    temp = pow((double)temp, (double)2);
    result += temp;
  }
  result = result/count;
  return result;
}

//---------------------------------------------------------------------------------
void catchPacket(DeviceInfo *deviceInfo, int *deviceCount){
  struct pkg_util_info *info = (struct pkg_util_info*)malloc(sizeof(struct pkg_util_info));
  rd_init(info);
  
  char errBuf[PCAP_ERRBUF_SIZE];
  typedef struct {
    u_char Control[2];
    u_char ID[2];
    u_char DestMac[6];
    u_char SrcMac[6];
  }ETHHEADER;
  
  pcap_t *device = pcap_open_live("wlan0", 65535, 1, 0, errBuf);
  
  void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    rd_init(info);
    uint16_t radiotap_len = radiotap_get(info, packet, pkthdr->len);   
    ETHHEADER *eth_header=(ETHHEADER*)(packet+radiotap_len);           
    
    char tempMac[20];
    sprintf(tempMac, "%02X-%02X-%02X-%02X-%02X-%02X",eth_header->SrcMac[0],eth_header->SrcMac[1],
	    eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
    //printf("Recieved_time: %s", ctime((const time_t*)&(pkthdr->ts.tv_sec)));
    if(info->Antenna_signal != 0){
      //printf("Antenna_signal: %d\n", info->Antenna_signal);
      int tempSignal = info->Antenna_signal;
      pthread_mutex_lock(&mutex);
      handleSignal(deviceInfo, tempMac, tempSignal, deviceCount);
      pthread_mutex_unlock(&mutex);
    }
  } 

  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);
  
  pcap_close(device);
}

void handleSignal(DeviceInfo *deviceInfo, char *mac, int signal, int *deviceCount){
  //printf("%s:%d\n", mac, signal);
  int pos = search(deviceInfo, mac, deviceCount);
  if (pos < 0){
    exit(EXIT_FAILURE); //crash
  } else {
    modify(deviceInfo, signal, pos);
  }
}

int search(DeviceInfo *deviceInfo, char *mac, int *deviceCount){
  int pos;
  for(pos = 0; pos < *deviceCount; pos++){
    if(strcmp(deviceInfo[pos].srcMac, mac) == 0){
      return pos;
    }
  }
  if(*deviceCount < MAX_DEVICE_COUNT){
    strcpy(deviceInfo[*deviceCount].srcMac, (const char*)mac);
    (*deviceCount)++;
    return (*deviceCount)-1;
  }
  return -1;
}

void modify(DeviceInfo *deviceInfo, int signal, int pos){
  deviceInfo[pos].signalCount++;
  if(deviceInfo[pos].signalCount <= MAX_SIGNAL_COUNT){
    deviceInfo[pos].signalSingle[deviceInfo[pos].signalCount-1] = signal;
    deviceInfo[pos].signalSum += signal;
  }
}


