#include "../NFC_Web_ESP32/Pn532I2c.h"
FakeWire Wire;
void queue(std::vector<uint8_t> cmd,std::vector<uint8_t> result,bool corrupt=false){Wire.expected.push_back({cmd,result,corrupt});}
void scanPrelude(std::vector<uint8_t> result){queue({0x32,1,0},{});queue({0x32,1,1},{});queue({0x4A,1,0},result);}
int main(){
 Pn532I2c n;
 queue({2},{0x32,1,6,7});queue({0x14,1,0x14,0},{});queue({0x32,5,255,1,0},{});assert(n.begin(21,22));
 scanPrelude({1,1,0,0x44,0,7,4,1,2,3,4,5,6});
 queue({0x40,1,0x60},{0,0,4,4,2,1,0,0x0F,3});assert(n.select());
 assert(n.userBytes==144 && n.uidLen==7 && n.uid[6]==6);
 uint8_t data[16]={};std::vector<uint8_t> response(17);for(int i=1;i<17;++i)response[i]=i;
 queue({0x40,1,0x30,4},response);assert(n.read16(4,data));assert(data[0]==1&&data[15]==16);
 queue({0x40,1,0xA2,4,1,2,3,4},{0});assert(n.writePage(4,data));
 queue({0x40,1,0x30,4},{0x14});assert(!n.read16(4,data));
 queue({0x40,1,0x30,4},response,true);assert(!n.read16(4,data));
 scanPrelude({0});assert(!n.select());assert(n.uidLen==0);
 scanPrelude({1,1,0,4,8,4,1,2,3,4});assert(n.select());assert(n.classicBlocks==64);
 uint8_t key[6]={255,255,255,255,255,255};
 queue({0x40,1,0x60,4,255,255,255,255,255,255,1,2,3,4},{0});assert(n.authenticate(4,key,false));
 assert(Wire.expected.empty());puts("PASS: PN532 frames/checksums, scan, NTAG detection, read/write, error status, Classic authentication");
}
