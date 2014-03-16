  1.airscan进一步删去了xmalloc.h和xmalloc.c文件  

  2.test.c代码实现了抓包+发送功能，发送格式为：
  时间|设备MAC|APMAC|强度均值|强度方差|接收次数
  
  注：tx_attenuation字段没有，另外时间以秒为单位，为当前时间距1970年1月1日的秒数
   
  3.AP程序执行方式： 
    sudo make
    sudo ./test
    
  4.服务端执行方式：
    gcc -o server server.c
    sudo ./server
    (可看到收到的约定格式的数据)
