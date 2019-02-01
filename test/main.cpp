#include "bls/bls.hpp"
#include <iostream>

using namespace std;
int main(){
   bls::init(0);
   bls::SecretKey sec;
   sec.init();
   bls::PublicKey pub;
   sec.getPublicKey(pub);
   cout<<pub<<endl;
   return 0;
}
