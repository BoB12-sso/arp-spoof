# send-arp-test
using arp request/reply  </br>
arp spoofing  

## Add
- get_ip  </br>
  get my ip  
- get_mac  </br>
get my mac  
  
- send_arp (in main.cpp)  </br>
  send normal ARP request victim's ip -> receive victim's mac address

## Modify
add const option for some header file function

## etc..
남이 만든 구조체나 소스를 가져다 쓰려면 그만큼 코딩에 대한 지식이 있어야겠구나... 라고 느낌(너무나...).  
스켈레톤 코드나 구조체 파일 절대 손 안대고 사용하려고했는데 const 말고는 답이 없어서 고쳤는데 조금 아쉽다.  
디버깅하면서 포인터에 대해 공부하는 느낌.. 좀 정확히 공부할 필요가 있어 보인다.
