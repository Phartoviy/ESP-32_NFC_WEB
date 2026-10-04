#include "../NFC_Web_ESP32/NdefCodec.h"
#include <assert.h>
#include <stdio.h>
#include <vector>
int main() {
  uint8_t out[900];
  const uint8_t hello[] = {'H','i'};
  const uint8_t expected[] = {3,9,0xD1,1,5,'T',2,'r','u','H','i',0xFE};
  assert(buildNdef(hello,2,false,out,sizeof(out)) == sizeof(expected));
  assert(memcmp(out,expected,sizeof(expected)) == 0);
  // All possible payload lengths and memory boundaries, including long TLV lengths.
  for (size_t len=0;len<270;++len) for (bool uri : {false,true}) {
    std::vector<uint8_t> input(len, 'a');
    size_t n=buildNdef(input.data(),len,uri,out,sizeof(out));
    if (len==0 || len>255-(uri?1:3)) { assert(n==0); continue; }
    assert(n>0 && out[n-1]==0xFE);
    assert(buildNdef(input.data(),len,uri,out,n-1)==0);
    assert(buildNdef(input.data(),len,uri,out,n)==n);
    size_t h=out[1]==255?4:2;
    size_t record=out[1]==255 ? (size_t(out[2])<<8)|out[3] : out[1];
    assert(record+h+1==n);
    assert(out[h]==0xD1 && out[h+2]==len+(uri?1:3));
    assert(memcmp(out+h+4+(uri?1:3),input.data(),len)==0);
  }
  assert(buildNdef(reinterpret_cast<const uint8_t*>("Привет"),12,false,out,144)==22);
  uint8_t key[6]; assert(parseHex("FF:ff 00 11 22 33",key,6));
  assert(key[0]==255 && key[5]==0x33);
  assert(!parseHex("FFFFFFFFFF",key,6)); assert(!parseHex("FFFFFFFFFFFF00",key,6));
  assert(!parseHex("GGFFFFFFFFFF",key,6)); assert(!parseHex("FFFFFFFFFFF",key,6));
  for(unsigned b=0;b<300;++b) {
    bool expectedData=b>0 && b<256 && (b<128 ? b%4!=3 : b%16!=15);
    assert(isClassicDataBlock(b,256)==expectedData);
    assert(isClassicDataBlock(b,64)==(b>0 && b<64 && b%4!=3));
  }
  puts("PASS: NDEF payloads/capacity/UTF-8, HEX parser, Classic protected blocks");
}
