#include <bls/bls.hpp>
#include <cybozu/test.hpp>
#include <cybozu/inttype.hpp>
#include <iostream>
#include <sstream>
#include <cybozu/benchmark.hpp>
#include <cybozu/sha2.hpp>
#include <map>
#include <algorithm>
#include <iterator>

using namespace bls;
using namespace std;
struct Provider {
    
    struct Sub_sec{
        Id recover_id;
        bls::SecretKey sec;
        PublicKey master_pub_key;
        Sub_sec(){}
        Sub_sec(Id _recover_id,bls::SecretKey _sec,PublicKey _master_pub_key):recover_id(_recover_id),sec(_sec),master_pub_key(_master_pub_key){}
        
        PublicKey get_sub_public_key()const{
            PublicKey res;
            sec.getPublicKey(res);
            return res;
        }
    };
    
    struct Recover_sig{
        
        uint32_t master_no; //which sub key sign
        Id recover_id;
        Signature sig;
        Recover_sig(){}
        Recover_sig(Id _recover_id,bls::Signature _sig):recover_id(_recover_id),sig(_sig){}
    };
    
    struct IdCmp{
        bool operator()(const Id & id1,const Id & id2)const{
            string str1,str2;
            id1.getStr(str1);
            id2.getStr(str2);
            return str1<str2;
        }
    };
    uint32_t owner_id;
    uint8_t t;
    uint8_t n;
    bls::SecretKey own_sec;
    bls::PublicKey own_pub;
    map<uint32_t,Sub_sec> other_subs; // No.->Sub sec
    map<uint32_t,Sub_sec> own_subs;   // No.->Sub sec
    
    //record pub(i,j)
    
    typedef map<Id,PublicKey,IdCmp> Id_PubKey_Map;
    map<uint32_t,Id_PubKey_Map > sub_pubs;
    
    PublicKey get_sub_public_key(uint32_t i,Id id){
        return sub_pubs[i][id];
    }
    
    void set_sub_public_key(uint32_t No,Id id,PublicKey pub_key){
        if(sub_pubs.count(No)==0){
            Id_PubKey_Map tmp;
            tmp[id]=pub_key;
            sub_pubs[No]=tmp;
        }
        else
            sub_pubs[No][id]=pub_key;
    }
    
    map<uint32_t,vector<Recover_sig> > recover_sigs;
    
    bls::SecretKeyVec msk;

    string current_message;
    
    Provider(){}
    Provider(uint32_t id,uint8_t _t,uint8_t _n):owner_id(id),t(_t),n(_n){
        own_sec.init();
        own_sec.getPublicKey(own_pub);
        own_sec.getMasterSecretKey(msk, t);

        for (int i = 0; i < n; i++) {
            int id = i + 1;
            Sub_sec rd;
            rd.sec.set(msk,id);
            rd.recover_id=id;
            rd.master_pub_key=own_pub;
            own_subs[id]=rd;
        }
    }
    
    void set_message(string m){current_message=m;}
    
    void broad_cast_sec_to_others(Provider& pvder){
        //if(pvder.owner_id==owner_id)
        //    return;
        pvder.set_other_sub(owner_id, own_subs[pvder.owner_id]);
        //pvder.set_sub_public_key(owner_id, own_subs[pvder.owner_id].recover_id,own_subs[pvder.owner_id].get_sub_public_key());
    }
    
    void broad_cast_sig_to_others(Provider* pvder,Recover_sig recover_sig){
        if(pvder->owner_id==owner_id)
            return;
        pvder->set_other_sig(recover_sig);
    }
    bool verify_sub_sig(uint32_t from_id,Recover_sig recover_sig){
        PublicKey pub=get_sub_public_key(from_id,recover_sig.recover_id);
        //cout<<"provider "<<from_id<< " public key:\n"<<pub<<endl;
        //cout<<"message:"<<current_message<<" sig:"<<recover_sig.sig<<endl;
        return recover_sig.sig.verify(pub, current_message);
    }
    void set_other_sub(uint32_t id,Sub_sec recover_detail){
        other_subs[id]=recover_detail;
    }
    
    void set_other_sig(Recover_sig recover_sig){
        uint32_t master_no=recover_sig.master_no;
        auto ok=verify_sub_sig(master_no,recover_sig);
        //cout<<"verify sub sig :"<<ok<<endl;
        cout<<"set owner_id:"<<owner_id<<" id:"<<master_no<<" recover_id:"<<recover_sig.recover_id<<endl;
        CYBOZU_TEST_ASSERT(ok);
        if(recover_sigs.count(master_no)==0){
            vector<Recover_sig> tmp;
            recover_sigs[master_no]=tmp;
        }
        recover_sigs[master_no].push_back(recover_sig);
    }
    
    bls::Signature recover(uint32_t id){
        if(id==owner_id)
            return bls::Signature() ;
        CYBOZU_TEST_ASSERT(recover_sigs.count(id)==1);
        vector<Recover_sig> sigs=recover_sigs[id];
        CYBOZU_TEST_ASSERT(sigs.size()>=t);
        bls::SignatureVec sigVecs(t);
        bls::IdVec idVecs(t);
        std::transform(sigs.begin(), sigs.end(),sigVecs.begin(),[&](Recover_sig & r_sig){return r_sig.sig;});
        std::transform(sigs.begin(), sigs.end(),idVecs.begin(),[&](Recover_sig & r_sig){return r_sig.recover_id;});
        
        bls::Signature sig;
        cout<<id<<endl;
        sig.recover(sigVecs, idVecs);
        return sig;
    };
    //sign using sub key of a provider
    void sub_sgin(Recover_sig &sig,uint32_t No){
        
        CYBOZU_TEST_ASSERT(other_subs.count(No)!=0);
        
        auto sec=other_subs[No].sec;
        sec.sign(sig.sig,current_message);
        sig.recover_id=other_subs[No].recover_id;
        sig.master_no=No;
        PublicKey pub;
        sec.getPublicKey(pub);
        //cout<<"sign messeage :"<<current_message<<" using pub key :\n"<<pub<<endl;
        
    }
    //sign using master key of this provider
    void sgin(bls::Signature &sig,string m){
        own_sec.sign(sig, m);
    }
    template <typename K,typename V>
    void static map_to_vec(const map<K,V> &from ,vector<V> & to){
        std::transform(from.begin(), from.end(),std::back_inserter(to),[&](std::pair<K, V> &kv){return kv.second;});
    }
};
std::ostream& operator<<(std::ostream& os, const Provider& provider)
{
    os<<"Owner Id :"<<provider.owner_id<<endl;
    os<<"Sec key:"<<provider.own_sec<<endl;
    os<<"Pub key :\n"<<provider.own_pub<<endl;
    
    os<<"\nOwn subs :"<<endl;
    
    for(const auto &own_sub:provider.own_subs){
        os<<own_sub.first<<": "<<"Recover Id: "<<own_sub.second.recover_id<<endl;
        os<<"Master Pub key :\n"<<own_sub.second.master_pub_key<<endl;
        os<<"Sub Pub key :\n"<<own_sub.second.get_sub_public_key()<<endl;
        
    }
    
    os<<"\nOther subs :"<<endl;
    
    os<<"Master key :\n"<<provider.other_subs.begin()->second.master_pub_key<<endl;
    for(const auto &own_sub:provider.other_subs){
        os<<own_sub.first<<": "<<"Recover Id: "<<own_sub.second.recover_id<<endl;
        os<<"Sub key :\n"<<own_sub.second.get_sub_public_key()<<endl;
        
    }
    
    os<<"\nSub Pub keys :"<<endl;
    
    for(const auto &sub_pub:provider.sub_pubs){
        os<<"from id :"<<sub_pub.first<<":"<<endl;
        for(const auto & pub:sub_pub.second){
            os<<"Recover id:"<<pub.first<<":"<<endl;
            os<<pub.second<<endl;
        }
    }
    return os;
}
void provider_test(){
    const uint8_t n=3;
    const uint8_t t=2;
    
    const string init_message="test";
    map<uint32_t,Provider> providers;
    
    //step1.1 init Provider (init sec ,sub secs and related ids )
    for(uint32_t i=1;i<=n;i++){
        providers[i]=Provider(i,t,n);
        providers[i].set_message(init_message);
        cout<<providers[i].own_sec<<endl;
    }
    //step1.2 set imformation to other povider
    for(uint32_t i=1;i<=n;i++){
        for(uint32_t j=1;j<=n;j++)
            providers[i].broad_cast_sec_to_others(providers[j]);
    }
    
    //step1.3 set sub pub key to other povider
    for(uint32_t i=1;i<=n;i++){
        auto &to_sets=providers[i].other_subs;
        for(uint32_t j=1;j<=n;j++){
            for(const auto &to_set:to_sets){
                //cout<<"set :"<<j <<" "<<to_set.first<<" "<<to_set.second.recover_id <<endl;
                providers[j].set_sub_public_key(to_set.first, to_set.second.recover_id, to_set.second.get_sub_public_key());}
        }
        
    }
    /*for(const auto &provider:providers){
        cout<<provider.second<<endl;
        uint32_t i=10;
    }*/
    //cout<<providers[2]<<endl;
    //step2  get public key of sub key
    
    
    //recover private key test
    
    SecretKeyVec    secs;
    IdVec           ids;
    
    uint32_t        test_no=1;
    for(uint32_t i=1;i<=t;i++){
        secs.push_back(providers[i].other_subs[test_no].sec);
        ids.push_back(providers[i].other_subs[test_no].recover_id);
    }
    
    SecretKey sk1;
    sk1.recover(secs, ids);
    
    CYBOZU_TEST_EQUAL(sk1,providers[test_no].own_sec);
    
    
    //step3 sig with sub key for message;and broadcast to others
    for(uint32_t i=1;i<=n;i++)
        for(uint32_t j=1 ;j<=n;j++){
            Provider::Recover_sig sigs;
            providers[i].sub_sgin(sigs,j);
            for(uint32_t k=1 ;k<=n;k++)
                providers[i].broad_cast_sig_to_others(&providers[k],sigs);
    }
    
    //step4 verify sub sign
    
    //step5 recover sub sign
    
    Signature origin_sigs[n][n];
    
    for(uint32_t i=1;i<=n;i++){
        for(uint32_t j=1;j<=n;j++){
            origin_sigs[i][j]= providers[i].recover(j);
        }
    }
    
    //step6 verify public key
    
    //step6.1 check if all sign same
    for(uint32_t i=1;i<=n;i++){
        for(uint32_t j=1;j<=n;j++){
            cout<<i<<j<<origin_sigs[i][j]<<endl;
            /*if(i!=j)
                CYBOZU_TEST_EQUAL(origin_sigs[i][0],origin_sigs[i][j]);
             */
            
        }
        
    }
}

void public_adds_test(){
    const uint32_t n=21;
    const string message="test";
    vector<SecretKey> secs;
    vector<PublicKey> pubs;
    vector<Signature> sigs;
    for(uint32_t i=0;i<n;i++){
        SecretKey sec;
        PublicKey pub;
        Signature sig;
        sec.init();
        //cout<<sec<<endl;
        secs.push_back(sec);
        sec.getPublicKey(pub);
        pubs.push_back(pub);
        sec.sign(sig,message);
        sigs.push_back(sig);
        if(i>=2){
            pubs[0].add(pubs[i]);
            sigs[0].add(sigs[i]);
            bool ok=sigs[0].verify(pubs[0], message);
            CYBOZU_TEST_ASSERT(sigs[0].verify(pubs[0], message));
        }
    }
    
}
template<class T>
void streamTest(const T& t)
{
	std::ostringstream oss;
	oss << t;
	std::istringstream iss(oss.str());
	T t2;
	iss >> t2;
	CYBOZU_TEST_EQUAL(t, t2);
}

template<class T>
void testSetForBN254()
{
	/*
		mask value to be less than r if the value >= (1 << (192 + 62))
	*/
	const uint64_t fff = uint64_t(-1);
	const uint64_t one = uint64_t(1);
	const struct {
		uint64_t in;
		uint64_t expected;
	} tbl[] = {
		{ fff, (one << 61) - 1 }, // masked with (1 << 61) - 1
		{ one << 62, 0 }, // masked
		{ (one << 62) | (one << 61), (one << 61) }, // masked
		{ (one << 61) - 1, (one << 61) - 1 }, // same
	};
	T t1, t2;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		uint64_t v1[] = { fff, fff, fff, tbl[i].in };
		uint64_t v2[] = { fff, fff, fff, tbl[i].expected };
		t1.set(v1);
		t2.set(v2);
		CYBOZU_TEST_EQUAL(t1, t2);
	}
}

void testForBN254()
{
	CYBOZU_TEST_EQUAL(bls::getOpUnitSize(), 4);
	bls::Id id;
	CYBOZU_TEST_ASSERT(id.isZero());
	id = 5;
	CYBOZU_TEST_EQUAL(id, 5);
	{
		const uint64_t id1[] = { 1, 2, 3, 4 };
		id.set(id1);
		std::ostringstream os;
		os << id;
		CYBOZU_TEST_EQUAL(os.str(), "0x4000000000000000300000000000000020000000000000001");
	}
	testSetForBN254<bls::Id>();
	testSetForBN254<bls::SecretKey>();
}

void hashTest(int type)
{
	bls::SecretKey sec;
	sec.init();
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	const std::string h = "\x01\x02\x03";
	bls::Signature sig;
	sec.signHash(sig, h);
	CYBOZU_TEST_ASSERT(sig.verifyHash(pub, h));
	CYBOZU_TEST_ASSERT(!sig.verifyHash(pub, "\x01\x02\04"));
	if (type == MCL_BN254) {
		CYBOZU_TEST_EXCEPTION(sec.signHash(sig, "", 0), std::exception);
		CYBOZU_TEST_EXCEPTION(sec.signHash(sig, "\x00", 1), std::exception);
		CYBOZU_TEST_EXCEPTION(sec.signHash(sig, "\x00\x00", 2), std::exception);
#ifndef BLS_SWAP_G
		const uint64_t c1[] = { 0x0c00000000000004ull, 0xcf0f000000000006ull, 0x26cd890000000003ull, 0x2523648240000001ull };
		const uint64_t mc1[] = { 0x9b0000000000000full, 0x921200000000000dull, 0x9366c48000000004ull };
		CYBOZU_TEST_EXCEPTION(sec.signHash(sig, c1, 32), std::exception);
		CYBOZU_TEST_EXCEPTION(sec.signHash(sig, mc1, 24), std::exception);
#endif
	}
}

void blsTest()
{
	bls::SecretKey sec;
	sec.init();
	streamTest(sec);
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	streamTest(pub);
	for (int i = 0; i < 5; i++) {
		std::string m = "hello";
		m += char('0' + i);
		bls::Signature sig;
		sec.sign(sig, m);
		CYBOZU_TEST_ASSERT(sig.verify(pub, m));
		CYBOZU_TEST_ASSERT(!sig.verify(pub, m + "a"));
		streamTest(sig);
		CYBOZU_BENCH_C("sign", 10000, sec.sign, sig, m);
		CYBOZU_BENCH_C("verify", 1000, sig.verify, pub, m);
	}
}
void k_of_nTest()
{
	const std::string m = "abc";
	const int n = 5;
	const int k = 3;
	bls::SecretKey sec0;
	sec0.init();
	bls::Signature sig0;
	sec0.sign(sig0, m);
	bls::PublicKey pub0;
	sec0.getPublicKey(pub0);
	CYBOZU_TEST_ASSERT(sig0.verify(pub0, m));

	bls::SecretKeyVec msk;
	sec0.getMasterSecretKey(msk, k);

	bls::SecretKeyVec allPrvVec(n);
	bls::IdVec allIdVec(n);
	for (int i = 0; i < n; i++) {
		int id = i + 1;
		allPrvVec[i].set(msk, id);
		allIdVec[i] = id;

		bls::SecretKey p;
		p.set(msk.data(), k, id);
		CYBOZU_TEST_EQUAL(allPrvVec[i], p);
	}

	bls::SignatureVec allSigVec(n);
	for (int i = 0; i < n; i++) {
		CYBOZU_TEST_ASSERT(allPrvVec[i] != sec0);
		allPrvVec[i].sign(allSigVec[i], m);
		bls::PublicKey pub;
		allPrvVec[i].getPublicKey(pub);
		CYBOZU_TEST_ASSERT(pub != pub0);
		CYBOZU_TEST_ASSERT(allSigVec[i].verify(pub, m));
	}

	/*
		3-out-of-n
		can recover
	*/
	bls::SecretKeyVec secVec(3);
	bls::IdVec idVec(3);
	for (int a = 0; a < n; a++) {
		secVec[0] = allPrvVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			secVec[1] = allPrvVec[b];
			idVec[1] = allIdVec[b];
			for (int c = b + 1; c < n; c++) {
				secVec[2] = allPrvVec[c];
				idVec[2] = allIdVec[c];
				bls::SecretKey sec;
				sec.recover(secVec, idVec);
				CYBOZU_TEST_EQUAL(sec, sec0);
				bls::SecretKey sec2;
				sec2.recover(secVec.data(), idVec.data(), secVec.size());
				CYBOZU_TEST_EQUAL(sec, sec2);
			}
		}
	}
	{
		secVec[0] = allPrvVec[0];
		secVec[1] = allPrvVec[1];
		secVec[2] = allPrvVec[0]; // same of secVec[0]
		idVec[0] = allIdVec[0];
		idVec[1] = allIdVec[1];
		idVec[2] = allIdVec[0];
		bls::SecretKey sec;
		CYBOZU_TEST_EXCEPTION_MESSAGE(sec.recover(secVec, idVec), std::exception, "same id");
	}
	{
		/*
			n-out-of-n
			can recover
		*/
		bls::SecretKey sec;
		sec.recover(allPrvVec, allIdVec);
		CYBOZU_TEST_EQUAL(sec, sec0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	secVec.resize(2);
	idVec.resize(2);
	for (int a = 0; a < n; a++) {
		secVec[0] = allPrvVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			secVec[1] = allPrvVec[b];
			idVec[1] = allIdVec[b];
			bls::SecretKey sec;
			sec.recover(secVec, idVec);
			CYBOZU_TEST_ASSERT(sec != sec0);
		}
	}
	/*
		3-out-of-n
		can recover
	*/
	bls::SignatureVec sigVec(3);
	idVec.resize(3);
	for (int a = 0; a < n; a++) {
		sigVec[0] = allSigVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			sigVec[1] = allSigVec[b];
			idVec[1] = allIdVec[b];
			for (int c = b + 1; c < n; c++) {
				sigVec[2] = allSigVec[c];
				idVec[2] = allIdVec[c];
				bls::Signature sig;
				sig.recover(sigVec, idVec);
				CYBOZU_TEST_EQUAL(sig, sig0);
			}
		}
	}
	{
		sigVec[0] = allSigVec[1]; idVec[0] = allIdVec[1];
		sigVec[1] = allSigVec[4]; idVec[1] = allIdVec[4];
		sigVec[2] = allSigVec[3]; idVec[2] = allIdVec[3];
		bls::Signature sig;
		CYBOZU_BENCH_C("sig.recover", 100, sig.recover, sigVec, idVec);
	}
	{
		/*
			n-out-of-n
			can recover
		*/
		bls::Signature sig;
		sig.recover(allSigVec, allIdVec);
		CYBOZU_TEST_EQUAL(sig, sig0);
	}
	/*
		2-out-of-n
		can't recover
	*/
	sigVec.resize(2);
	idVec.resize(2);
	for (int a = 0; a < n; a++) {
		sigVec[0] = allSigVec[a];
		idVec[0] = allIdVec[a];
		for (int b = a + 1; b < n; b++) {
			sigVec[1] = allSigVec[b];
			idVec[1] = allIdVec[b];
			bls::Signature sig;
			sig.recover(sigVec, idVec);
			CYBOZU_TEST_ASSERT(sig != sig0);
		}
	}
	// share and recover publicKey
	{
		bls::PublicKeyVec pubVec(k);
		idVec.resize(k);
		// select [0, k) publicKey
		for (int i = 0; i < k; i++) {
			allPrvVec[i].getPublicKey(pubVec[i]);
			idVec[i] = allIdVec[i];
		}
		bls::PublicKey pub;
		pub.recover(pubVec, idVec);
		CYBOZU_TEST_EQUAL(pub, pub0);
		bls::PublicKey pub2;
		pub2.recover(pubVec.data(), idVec.data(), pubVec.size());
		CYBOZU_TEST_EQUAL(pub, pub2);
	}
}
void popTest()
{
	const size_t k = 3;
	const size_t n = 6;
	const std::string m = "pop test";
	bls::SecretKey sec0;
	sec0.init();
	bls::PublicKey pub0;
	sec0.getPublicKey(pub0);
	bls::Signature sig0;
	sec0.sign(sig0, m);
	CYBOZU_TEST_ASSERT(sig0.verify(pub0, m));

	bls::SecretKeyVec msk;
	sec0.getMasterSecretKey(msk, k);

	bls::PublicKeyVec mpk;
	bls::getMasterPublicKey(mpk, msk);
	bls::SignatureVec  popVec;
	bls::getPopVec(popVec, msk);

	for (size_t i = 0; i < popVec.size(); i++) {
		CYBOZU_TEST_ASSERT(popVec[i].verify(mpk[i]));
	}

	const int idTbl[n] = {
		3, 5, 193, 22, 15
	};
	bls::SecretKeyVec secVec(n);
	bls::PublicKeyVec pubVec(n);
	bls::SignatureVec sVec(n);
	for (size_t i = 0; i < n; i++) {
		int id = idTbl[i];
		secVec[i].set(msk, id);
		secVec[i].getPublicKey(pubVec[i]);
		bls::PublicKey pub;
		pub.set(mpk, id);
		CYBOZU_TEST_EQUAL(pubVec[i], pub);

		bls::Signature pop;
		secVec[i].getPop(pop);
		CYBOZU_TEST_ASSERT(pop.verify(pubVec[i]));

		secVec[i].sign(sVec[i], m);
		CYBOZU_TEST_ASSERT(sVec[i].verify(pubVec[i], m));
	}
	secVec.resize(k);
	sVec.resize(k);
	bls::IdVec idVec(k);
	for (size_t i = 0; i < k; i++) {
		idVec[i] = idTbl[i];
	}
	bls::SecretKey sec;
	sec.recover(secVec, idVec);
	CYBOZU_TEST_EQUAL(sec, sec0);
	bls::Signature sig;
	sig.recover(sVec, idVec);
	CYBOZU_TEST_EQUAL(sig, sig0);
	bls::Signature sig2;
	sig2.recover(sVec.data(), idVec.data(), sVec.size());
	CYBOZU_TEST_EQUAL(sig, sig2);
}

void addTest()
{
	bls::SecretKey sec1, sec2;
	sec1.init();
	sec2.init();
	CYBOZU_TEST_ASSERT(sec1 != sec2);

	bls::PublicKey pub1, pub2;
	sec1.getPublicKey(pub1);
	sec2.getPublicKey(pub2);

	const std::string m = "doremi";
	bls::Signature sig1, sig2;
	sec1.sign(sig1, m);
	sec2.sign(sig2, m);
	CYBOZU_TEST_ASSERT((sig1 + sig2).verify(pub1 + pub2, m));
}

void aggregateTest()
{
	const size_t n = 10;
	bls::SecretKey secs[n];
	bls::PublicKey pubs[n], pub;
	bls::Signature sigs[n], sig;
	const std::string m = "abc";
	for (size_t i = 0; i < n; i++) {
		secs[i].init();
		secs[i].getPublicKey(pubs[i]);
		secs[i].sign(sigs[i], m);
	}
	pub = pubs[0];
	sig = sigs[0];
	for (size_t i = 1; i < n; i++) {
		pub.add(pubs[i]);
		sig.add(sigs[i]);
	}
	CYBOZU_TEST_ASSERT(sig.verify(pub, m));
}

void dataTest()
{
	const size_t FrSize = bls::getFrByteSize();
	const size_t FpSize = bls::getG1ByteSize();
	bls::SecretKey sec;
	sec.init();
	std::string str;
	sec.getStr(str, bls::IoFixedByteSeq);
	{
		CYBOZU_TEST_EQUAL(str.size(), FrSize);
		bls::SecretKey sec2;
		sec2.setStr(str, bls::IoFixedByteSeq);
		CYBOZU_TEST_EQUAL(sec, sec2);
	}
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	pub.getStr(str, bls::IoFixedByteSeq);
	{
#ifdef BLS_SWAP_G
		CYBOZU_TEST_EQUAL(str.size(), FpSize);
#else
		CYBOZU_TEST_EQUAL(str.size(), FpSize * 2);
#endif
		bls::PublicKey pub2;
		pub2.setStr(str, bls::IoFixedByteSeq);
		CYBOZU_TEST_EQUAL(pub, pub2);
	}
	std::string m = "abc";
	bls::Signature sign;
	sec.sign(sign, m);
	sign.getStr(str, bls::IoFixedByteSeq);
	{
#ifdef BLS_SWAP_G
		CYBOZU_TEST_EQUAL(str.size(), FpSize * 2);
#else
		CYBOZU_TEST_EQUAL(str.size(), FpSize);
#endif
		bls::Signature sign2;
		sign2.setStr(str, bls::IoFixedByteSeq);
		CYBOZU_TEST_EQUAL(sign, sign2);
	}
	bls::Id id;
	const uint64_t v[] = { 1, 2, 3, 4, 5, 6, };
	id.set(v);
	id.getStr(str, bls::IoFixedByteSeq);
	{
		CYBOZU_TEST_EQUAL(str.size(), FrSize);
		bls::Id id2;
		id2.setStr(str, bls::IoFixedByteSeq);
		CYBOZU_TEST_EQUAL(id, id2);
	}
}

void verifyAggregateTest()
{
	const size_t n = 10;
	bls::SecretKey secs[n];
	bls::PublicKey pubs[n];
	bls::Signature sigs[n], sig;
	const size_t sizeofHash = 32;
	struct Hash { char data[sizeofHash]; };
	std::vector<Hash> h(n);
	for (size_t i = 0; i < n; i++) {
		char msg[128];
		CYBOZU_SNPRINTF(msg, sizeof(msg), "abc-%d", (int)i);
		const size_t msgSize = strlen(msg);
		cybozu::Sha256().digest(h[i].data, sizeofHash, msg, msgSize);
		secs[i].init();
		secs[i].getPublicKey(pubs[i]);
		secs[i].signHash(sigs[i], h[i].data, sizeofHash);
	}
	sig = sigs[0];
	for (size_t i = 1; i < n; i++) {
		sig.add(sigs[i]);
	}
	CYBOZU_TEST_ASSERT(sig.verifyAggregatedHashes(pubs, h.data(), sizeofHash, n));
	bls::Signature invalidSig = sigs[0] + sigs[1];
	CYBOZU_TEST_ASSERT(!invalidSig.verifyAggregatedHashes(pubs, h.data(), sizeofHash, n));
	h[0].data[0]++;
	CYBOZU_TEST_ASSERT(!sig.verifyAggregatedHashes(pubs, h.data(), sizeofHash, n));
}

void testAll()
{
    public_adds_test();
    //blsTest();
    //provider_test();
	

	/*
     k_of_nTest();
	popTest();
	addTest();
	dataTest();
	aggregateTest();
	verifyAggregateTest();
    */
}
CYBOZU_TEST_AUTO(all)
{
	const struct {
		int type;
		const char *name;
	} tbl[] = {
		{ MCL_BN254, "BN254" },
#if MCLBN_FP_UNIT_SIZE == 6 && MCLBN_FR_UNIT_SIZE == 6
		{ MCL_BN381_1, "BN381_1" },
#endif
#if MCLBN_FP_UNIT_SIZE == 6 && MCLBN_FR_UNIT_SIZE == 4
		{ MCL_BLS12_381, "BLS12_381" },
#endif
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		printf("curve=%s\n", tbl[i].name);
		int type = tbl[i].type;
		bls::init(type);
		if (type == MCL_BN254) {
			testForBN254();
		}
		testAll();
		hashTest(type);
	}
}
