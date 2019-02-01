#include <bls/bls_256_lib.hpp>
#include <iostream>
using namespace std;

int main(int argc, char** argv) {
   
   bls::init(0);
   bls::SecretKey sec;
   sec.init();
   bls::PublicKey pub;
   sec.getPublicKey(pub);
   cout<<pub<<endl;
   
   
   return 0;
}

