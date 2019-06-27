#include <bls/bls_256_lib.hpp>
#include <cybozu/sha2.hpp>
#include <iostream>
using namespace std;
const size_t sizeofHash = 32;
struct Hash { char data[sizeofHash]; };

struct sign_group{
   sign_group(string str,uint16_t n=10){
      cybozu::Sha256().digest(hash.data, sizeofHash, str.c_str(), sizeof(str));
      for(uint16_t i=0;i<n;i++){
         bls::SecretKey sec;
         sec.init();
         secs.emplace_back(sec);
         bls::PublicKey   pub;
         sec.getPublicKey(pub);
         if(i==0)
            sum_pub=pub;
         else
            sum_pub.add(pub);
      }
   }
   
   bool sign(){
      
      for(uint16_t i=0;i<secs.size();i++){
         bls::Signature sig;
         secs[i].signHash(sig, hash.data,sizeofHash);
         sigs.emplace_back(sig);
         if(i==0)
            sum_sig=sig;
         else
            sum_sig.add(sig);
      }
      return sum_sig.verifyHash(sum_pub, hash.data,sizeofHash);
   }
   vector<bls::SecretKey> secs;
   vector<bls::Signature> sigs;
   bls::Signature         sum_sig;
   bls::PublicKey         sum_pub;
   Hash hash;
};

int main(int argc, char** argv) {
   
   bls::init(0);
   /*
   bls::SecretKey sec;
   sec.init();
   bls::PublicKey pub;
   sec.getPublicKey(pub);
   char buf[1024];
   //auto n=blsPublicKeySerialize(buf,sizeof(buf),&pub);
   auto n=blsPublicKeySerialize(buf,sizeof(buf) , <#const blsPublicKey *pub#>)
   
   bls::SecretKey sec1;
   blsSecretKey sec,sec2;

   string sec_hex="d6e71cafe0b29ac7f738f2278a4088d0eec1400db453235834d288d4f04c5a11";
   
   sec1.setStr(sec_hex);
   auto n=blsSecretKeySetHexStr(&sec,sec_hex.c_str(),64);
   
   char sec_hex2[1000];
   n=blsSecretKeyGetHexStr(sec_hex2,64,&sec);
   cout<<"sec:"<<sec_hex2<<endl;
   
   n=blsSecretKeySetHexStr(&sec2,sec_hex2,64);
   
   auto x=blsSecretKeyIsEqual(&sec, &sec2);
   
   blsPublicKey pub;
   blsGetPublicKey(&pub,&sec);
   
   char pub_hex[1000];
   blsPublicKeyGetHexStr(pub_hex,sizeof(pub_hex),&pub);
   cout<<pub_hex<<endl;
   
   
   bls::SecretKey  sec1,sec2;
   bls::PublicKey  pub1,pub2;
   
   string str1="a";
   string str2="a";

   std::vector<Hash> hashs(2);
   
   cybozu::Sha256().digest(hashs[0].data, sizeofHash, str1.c_str(), sizeof(str1));
   cybozu::Sha256().digest(hashs[1].data, sizeofHash, str2.c_str(), sizeof(str2));
   
   
   sec1.init();
   sec2.init();
   
   sec1.getPublicKey(pub1);
   sec2.getPublicKey(pub2);
   
   bls::Signature sig1;
   bls::Signature sig2;
   
   sec1.signHash(sig1,hashs[0].data,sizeofHash);
   sec2.signHash(sig2,hashs[1].data,sizeofHash);
   
   sig1.add(sig2);
   vector<blsPublicKey> pub_keys;
   vector<bls::PublicKey> bls_pub_keys;
   vector<string> strs;
   pub_keys.push_back(pub1.self_);
   pub_keys.push_back(pub2.self_);
   bls_pub_keys.push_back(pub1);
   bls_pub_keys.push_back(pub2);
   strs.push_back(str1);
   strs.push_back(str2);
   auto ok =sig1.verifyAggregatedHashes(&bls_pub_keys[0], hashs.data(),sizeofHash,2);
   auto ok2=sig2.verifys(pub_keys,strs);
   //sig1.verify(<#const PublicKey &pub#>, <#const void *m#>, <#size_t size#>)
   */
   
   vector<sign_group> sign_groups;
   vector<bls::PublicKey> bls_pub_keys;
   vector<Hash> hashs;
   bls::Signature         sum_sig;
   const uint32_t max=100;
   for(uint i=0;i<max;i++){
      sign_groups.emplace_back(sign_group(cybozu::itoa(i)));
      cout<<sign_groups[i].sign()<<endl;
      hashs.emplace_back(sign_groups[i].hash);
      bls_pub_keys.emplace_back(sign_groups[i].sum_pub);
      if(i==0)
         sum_sig=sign_groups[i].sum_sig;
      else
         sum_sig.add(sign_groups[i].sum_sig);
   }
   auto ok =sum_sig.verifyAggregatedHashes(&bls_pub_keys[0], hashs.data(),sizeofHash,max);
   
   return 0;
}

