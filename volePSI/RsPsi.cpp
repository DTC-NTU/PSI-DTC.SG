#include "RsPsi.h"
#include <array>
#include <future>
#include "coproto/coproto.h"
#include <string>
#include <vector>
#include <chrono> //WJ
// TKL for osn
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "osn/OSNReceiver.h"
// TKL
// #include "thirdparty/parallel-hashmap/parallel_hashmap/phmap.h"
namespace volePSI
{

    template <typename T>
    struct Buffer : public span<T>
    {
        std::unique_ptr<T[]> mPtr;

        void resize(u64 s)
        {
            mPtr.reset(new T[s]);
            static_cast<span<T> &>(*this) = span<T>(mPtr.get(), s);
        }
    };

    void details::RsPsiBase::init(
        u64 senderSize,
        u64 recverSize,
        u64 statSecParam,
        block seed,
        bool malicious,
        u64 numThreads,
        bool useReducedRounds)
    {
        mSenderSize = senderSize;
        mRecverSize = recverSize;
        mSsp = statSecParam;
        mPrng.SetSeed(seed);
        mMalicious = malicious;

        mMaskSize = malicious ? sizeof(block) : std::min<u64>(oc::divCeil(mSsp + oc::log2ceil(mSenderSize * mRecverSize), 8), sizeof(block));
        mCompress = mMaskSize != sizeof(block);

        mNumThreads = numThreads;
        mUseReducedRounds = useReducedRounds;
    }

    namespace
    {
        struct NoHash
        {
            inline size_t operator()(const block &v) const
            {
                return v.get<size_t>(0);
            }
        };
    }

    // WJ : Simple Hashs PSI
    task<> RsPsi3rdPSenderB::runSpHshPSI(span<block> inputs, Socket &chl, Socket &ch2) // chl to Alice ; ch2 to SHS
    {

        auto psiseed = block{};
        auto hashes = span<block>{};
        auto data = std::unique_ptr<block[]>{};
        setTimePoint("BOB : run-PSI begin");
        co_await (chl.recv(psiseed));
        //   std::cout << "BOB : recved psiseed = " << psiseed << std::endl;

        data = std::unique_ptr<block[]>(new block[mSenderSize]);
        hashes = span<block>(data.get(), mSenderSize);

        mAEShash.setKey(psiseed);
        mAEShash.hashBlocks(inputs, hashes);

        //    MC_AWAIT(ch2.send(std::move(hashes)));
        co_await (ch2.send(hashes));
        //    std::cout << "Bob : send hashes done." << std::endl;

        // for testing only
        /*         {
                    std::cout << "Bob sends theirHashes :" <<std::endl;
                    for (u64 i = 0; i < mSenderSize; i++)
                    {
                        std::cout << hashes[i] << ", ";
                    }
                    std::cout << std::endl;
                }      */
        setTimePoint("BOB : run-sendHash");
        // std::cout << "Bob receives from Alice" << chl.bytesReceived() << std::endl;
    }

    Proto RsPsi3rdPSenderB::runSpHshPsiOsn(Socket &chl, Socket &ch2, std::vector<block> &sendSet, std::vector<block> &payloadSet) // chl: to Alice; ch2: to SHS
    {
        setTimePoint("BOB : enter protocol");
        setSenderSize(sendSet.size());
        co_await (ch2.send(sendSet.size()));
        //    MC_AWAIT(ch2.recv(otherSetSize));
        co_await (runSpHshPSI(sendSet, chl, ch2)); // 1st socket to Alice ; 2nd socket to SHS
                                                   //    MC_AWAIT(chl.flush());
                                                   //    MC_AWAIT(ch2.flush());
        setTimePoint("BOB : PSI is done");

        co_await (ch2.recv(mCardinality)); // recv cardinality frem server

        getOSNReceiver().init(sendSet.size(), 1); // TKL

        setTimePoint("BOB : before run_osn");

        co_await (getOSNReceiver().run_osn(payloadSet, ch2, mReceiver_shares));

        setTimePoint("BOB : after run_osn");
        // mSenderA_shares.resize(mReceiver_shares.size());
        mSenderA_shares.resize(mCardinality);
        co_await (ch2.recv(mSenderA_shares)); // recv senderB's shares
        setTimePoint("BOB : Receive shares from SHS");

        myPi_SdrB.resize(mCardinality);
        co_await (ch2.recv(myPi_SdrB));
    }

    // WJ: run simple hash psi, Alice
    task<> RsPsi3rdPSenderA::runSpHshPSI(span<block> inputs, Socket &chl, Socket &ch2) // chl: to Bob; ch2: to SHS
    {

        auto data = std::unique_ptr<block[]>{};
        auto myHashes = span<block>{};
        auto psiSeed = block{};
        setTimePoint("ALICE : run-PSI begin");

        psiSeed = mSpH_prng.get();
        //   std::cout << "Alice : psiSeed" << psiSeed << std::endl;
        co_await (chl.send(psiSeed));
        data = std::unique_ptr<block[]>(new block[mRecverSize]);
        myHashes = span<block>(data.get(), mRecverSize);
        mAEShash.setKey(psiSeed);
        mAEShash.hashBlocks(inputs, myHashes); // WJ, H(X) = AES(X) + X
        co_await (ch2.send(myHashes));
        //   MC_AWAIT(ch2.send(std::move(myHashes)));
        //   std::cout << "Alice : send myHashes done." << std::endl;
        // for testing only
        /* std::cout << "Alice sends myHashes : " << std::endl;
        {

            for (u64 i = 0; i < mRecverSize; i++)
            {
                std::cout << myHashes[i] << ", ";
            }
            std::cout << std::endl;
        }  */
        setTimePoint("ALICE : run-sendHash");
        std::cout << "Alice sends to Bob: " << chl.bytesSent() << " Bytes." << std::endl;
    }

    Proto RsPsi3rdPSenderA::runSpHshPsiOsn(Socket &chl, Socket &ch2, std::vector<block> &recverSet, std::vector<block> &payloadSet) // chl: to Bob; ch2: to SHS
    {
        setTimePoint("ALICE : enter protocol");
        setRecverSize(recverSet.size());
        initSpH_prng();
        co_await (ch2.send(recverSet.size()));
        // MC_AWAIT(ch2.recv(otherSetSize));
        co_await (runSpHshPSI(recverSet, chl, ch2));
        //        MC_AWAIT(chl.flush());
        //        MC_AWAIT(ch2.flush());
        setTimePoint("ALICE : PSI is done");
        co_await (ch2.recv(mCardinality));          // recv cardinality frem server
        getOSNReceiver().init(recverSet.size(), 1); // TKL

        setTimePoint("ALICE : before run_osn");

        co_await (getOSNReceiver().run_osn(payloadSet, ch2, mReceiver_shares));

        setTimePoint("ALICE : after run_osn");
        // mSenderB_shares.resize(mReceiver_shares.size());
        mSenderB_shares.resize(mCardinality);
        co_await (ch2.recv(mSenderB_shares)); // recv senderB's shares
        setTimePoint("ALICE : Receive shares from SHS");
        // MC_AWAIT(ch2.recv(mCardinality));
        myPi_SdrA.resize(mCardinality);
        co_await (ch2.recv(myPi_SdrA));
    }

    // WJ : Simple hash psi
    /*void RsPsi3rdPReceiver::setmIntersectionB()
    {

        for (u64 i = 0; i < 10; i++)
        {
            mIntersectionB.push_back(i);
        }

    }*/
    task<> RsPsi3rdPReceiver::runSpHshPSI(Socket &chl, Socket &ch2) // chl: to Bob; ch2: to Alice
    {
        auto data = std::unique_ptr<block[]>{};
        auto myHashes = span<block>{};
        auto theirHashes = span<block>{};
        auto map_hash = google::dense_hash_map<block, u64, NoHash>{};
        //         map_hash = std::map<block, u64>{},
        auto i = u64{};
        //          mask = block{}

        setTimePoint("SHS : run-PSI begin");
        mIntersectionA.clear();
        mIntersectionB.clear();
        data = std::unique_ptr<block[]>(new block[mSenderSize +
                                                  mRecverSize]);

        myHashes = span<block>(data.get(), mRecverSize);
        theirHashes = span<block>(data.get() + mRecverSize, mSenderSize);
        //   std::cout << "SHS : Before reaceiving hashes" << std::endl;
        co_await (ch2.recv(myHashes));
        //        MC_AWAIT(ch2.flush());
        //    std::cout << "SHS : myHashes reaceived" << std::endl;
        co_await (chl.recv(theirHashes));
        //        MC_AWAIT(chl.flush());
        //   std::cout << "SHS : theirHashes reaceived" << std::endl;

        if (myHashes.size() != mRecverSize || theirHashes.size() != mSenderSize)
            throw RTE_LOC;

        //    std::cout<< "SHS : myHashes size and theirHashes size match! "  << std::endl;
        //      MC_AWAIT(macoro::when_all_ready(ch2.recv(myHashes),chl.recv(theirHashes)));
        map_hash.resize(myHashes.size());
        map_hash.set_empty_key(oc::ZeroBlock);
        for (i = 0; i < mRecverSize; i++)
        {
            map_hash.insert({myHashes[i], i});
        }

        { // this pair of brackets are important.
            block h = oc::ZeroBlock;
            auto iter = theirHashes.data();
            // std::cout << "SHS memcpy from theirHashes : " << std::endl;
            for (i = 0; i < mSenderSize; ++i)
            {
                memcpy(&h, iter, 16);
                iter += 1;
                // std::cout << h << ", " ;
                auto iter = map_hash.find(h);
                if (iter != map_hash.end())
                {
                    mIntersectionA.push_back(iter->second); // WJ: contains indices of matched items w.r.t. PSI receiver Alice's set
                    mIntersectionB.push_back(i);            // WJ:  contains indices of matched items w.r.t. PSI sender Bob's set
                }
            }
            //   std::cout << std::endl;
        }
        setTimePoint("SHS : run-found");

        /*    // for testing only
              std::cout << "SHS receives from Alice the myHashes : " << std::endl;
               for ( i = 0; i < mRecverSize; i++)
               {
                    std::cout << myHashes[i] <<", ";
               }
               std::cout << std::endl;

               std::cout << "SHS receives from Bob the theirHashes : " << std::endl;
               for ( i = 0; i < mSenderSize; i++)
               {
                    std::cout << theirHashes[i] <<", ";
               }
               std::cout << std::endl;
               std::cout << "SHS saves from Alice the myHashes in map_hash : " << std::endl;
                for (const auto& pair : map_hash) {
                        std::cout << pair.first << ": " << pair.second << std::endl;
                }
                */
    }

    task<> RsPsi3rdPReceiver::run_OSN_Ssingle(Socket &chl, OSNSender &OsnSender, std::vector<u64> intersection,
                                              size_t size, std::vector<block> &sender_shares)
    {
        std::vector<int> myPi;
        std::map<int, int> i2loc{};
        //    std::chrono::high_resolution_clock::time_point time_start, time_end;
        osuCrypto::Timer::timeUnit time_start, time_end;
        // TKL start of OSN
        setTimePoint("SHS : enter OSN");
        // if (mTimer)
        //     mRecver.setTimer(getTimer());

        setTimePoint("SHS : OSN begin");
        mCardinality = intersection.size();
        co_await (chl.send(intersection.size()));
        OsnSender.init_wj(size, 1, "benes", i2loc); // WJ: "benes" is needed to read from cache; to be moved in offline phase
        setTimePoint("SHS : OSN init");
        myPi = OsnSender.getmyPi(i2loc, intersection);
        OsnSender.setPi(myPi);
        setTimePoint("SHS : get myPi");
        //            time_start = std::chrono::high_resolution_clock::now();
        //         time_start = setTimePoint("SHS : before run_osn");
        co_await (OsnSender.run_osn(chl, sender_shares));
        //         time_end = setTimePoint("SHS : after run_osn");
        //        MC_AWAIT(chl.send(sender_shares));
        //            time_end = std::chrono::high_resolution_clock::now();

        // TKL end of OSN
    }

    Proto RsPsi3rdPReceiver::runSpHshPsiOsn(Socket &chl, Socket &ch2) // chl: to Bob ;  ch2: to Alice
    {
        std::vector<int> myPiA, myPiB;
        std::vector<block> interPLA, interPLB;
        setTimePoint("SHS : enter protocol");

        co_await (macoro::when_all_ready(ch2.recv(mRecverSize), chl.recv(mSenderSize)));
        //        MC_AWAIT(macoro::when_all_ready(ch2.send(mSenderSize),chl.send(mRecverSize)));
        co_await (runSpHshPSI(chl, ch2));
        setTimePoint("SHS : PSI is done.");

        co_await (macoro::when_all_ready(run_OSN_Ssingle(ch2, mOsnSenderA, mIntersectionA, mRecverSize, mSenderA_shares),
                                         run_OSN_Ssingle(chl, mOsnSenderB, mIntersectionB, mSenderSize, mSenderB_shares)));

        myPiA.resize(mIntersectionA.size());
        myPiA = mOsnSenderA.getPi();
        myPiB.resize(mIntersectionB.size());
        myPiB = mOsnSenderB.getPi();
        for (auto i = 0; i < myPiA.size(); i++)
        {
            auto j1 = myPiA[i];
            interPLA.push_back(mSenderA_shares[j1]);
            auto j2 = myPiB[i];
            interPLB.push_back(mSenderB_shares[j2]);
        }

        co_await (macoro::when_all_ready(chl.send(interPLA), ch2.send(interPLB)));
        //        MC_AWAIT(macoro::when_all_ready(chl.send(mSenderA_shares),ch2.send(mSenderB_shares)));
        setTimePoint("SHS : osn shares sent to A B");

        co_await (macoro::when_all_ready(chl.send(std::move(myPiB)), ch2.send(std::move(myPiA))));
    }

}