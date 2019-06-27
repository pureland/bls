#include <bls/bls_256_lib.hpp>
#include <iostream>
#include <time.h>
#include <unistd.h>
#include <cybozu/sha2.hpp>

using namespace std;
const uint16_t sizeofHash=32;
struct Hash { char data[sizeofHash]; };

struct sign_group{
   sign_group(string str,uint16_t n=10){
      cybozu::Sha256().digest(hash.data, sizeofHash, str.c_str(), sizeof(str));
      for(uint16_t i=0;i<n;i++){
         bls::SecretKey sec;
         bls::Signature sig;
         sec.init();
         bls::PublicKey   pub;
         sec.getPublicKey(pub);
         sec.signHash(sig, hash.data,sizeofHash);
         if(i==0){
            sum_pub=pub;
            sum_sig=sig;
         }
         else{
            sum_pub.add(pub);
            sum_sig.add(sig);
         }
      }
   }
   
   bool sign(){
      
      for(uint16_t i=0;i<secs.size();i++){
         bls::Signature sig;
         secs[i].signHash(sig, hash.data,sizeofHash);
         //sigs.emplace_back(sig);
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

class run_time{
public:
   run_time(string log){
      old_s=time(NULL);
      old_mm=clock();

      cout<<log<<endl;
   }
   void how_long(string log){
      
      auto now_s=time(NULL);
      auto now_mm=clock();

      
      cout<<log<<" use :"<<now_s-old_s+double(now_mm-old_mm)/1000000 <<"s"<<endl;
      old_mm=now_mm;
      old_s=now_s;
   }
   clock_t old_mm;
   time_t old_s;
   
};
int main(int argc, char** argv) {
   const uint32_t max=500;
   const uint32_t group_size=200;
   bls::init(0);
   
   vector<sign_group> sign_groups;
   vector<bls::PublicKey> bls_pub_keys;
   vector<Hash> hashs;
   bls::Signature         sum_sig;

   for(uint i=0;i<max;i++){
      sign_groups.emplace_back(sign_group(cybozu::itoa(i),group_size));

      hashs.emplace_back(sign_groups[i].hash);
      bls_pub_keys.emplace_back(sign_groups[i].sum_pub);
      if(i==0)
         sum_sig=sign_groups[i].sum_sig;
      else
         sum_sig.add(sign_groups[i].sum_sig);
   }
   run_time time("start verify");
   auto ok =sum_sig.verifyAggregatedHashes(&bls_pub_keys[0], hashs.data(),sizeofHash,max);
   
   time.how_long("verify use :");
   
   return 0;
}

