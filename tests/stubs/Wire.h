#pragma once
#include <vector>
#include <deque>
#include <assert.h>
#include <stdint.h>
struct Expected { std::vector<uint8_t> command, response; bool corrupt=false; };
class FakeWire {
 public:
 std::deque<Expected> expected;
 std::vector<uint8_t> tx,rx,response;
 size_t at=0;
 void begin(int,int,int) {} void setTimeOut(int) {}
 void beginTransmission(uint8_t address) { assert(address==0x24);tx.clear(); }
 size_t write(const uint8_t* p,size_t n) {tx.assign(p,p+n);return n;}
 int endTransmission() {
  if(tx.size()==6) {response.clear();return 0;}
  assert(!expected.empty()); auto e=expected.front();expected.pop_front();
  assert(tx.size()==e.command.size()+8);
  assert(tx[0]==0 && tx[1]==0 && tx[2]==255 && tx[5]==0xD4);
  assert(uint8_t(tx[3]+tx[4])==0);
  uint8_t sum=0;for(size_t i=5;i<tx.size()-1;++i)sum+=tx[i];assert(sum==0);
  for(size_t i=0;i<e.command.size();++i)assert(tx[6+i]==e.command[i]);
  uint8_t len=e.response.size()+2;
  response={1,0,0,255,len,uint8_t(0-len),0xD5,uint8_t(e.command[0]+1)};
  response.insert(response.end(),e.response.begin(),e.response.end());
  sum=0;for(size_t i=6;i<response.size();++i)sum+=response[i];
  response.push_back(uint8_t(0-sum));response.push_back(0);response.resize(64);
  if(e.corrupt)response[8]^=1;
  return 0;
 }
 size_t requestFrom(uint8_t address,uint8_t count) {
  assert(address==0x24);at=0;
  if(count==1) rx={uint8_t(response.empty()?0:1)};
  else if(count==7)rx={1,0,0,255,0,255,0};
  else{assert(count==64);rx=response;response.clear();}
  return rx.size();
 }
 int read(){assert(at<rx.size());return rx[at++];}
};
extern FakeWire Wire;
