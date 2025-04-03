#include "RsPsi.h"
#include <array>
#include <future>
#include "coproto/coproto.h"
#include <string>
#include <vector>
#include <chrono>

#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "osn/OSNReceiver.h"

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

    task<> RsPsi3rdPSenderB::runSpHshPSI(span<block> inputs, Socket &chl, Socket &ch2)
    {

        auto psiseed = block{};
        auto hashes = span<block>{};
        auto data = std::unique_ptr<block[]>{};
        setTimePoint("BOB : run-PSI begin");
        co_await (chl.recv(psiseed));

        data = std::unique_ptr<block[]>(new block[mSenderSize]);
        hashes = span<block>(data.get(), mSenderSize);

        mAEShash.setKey(psiseed);
        mAEShash.hashBlocks(inputs, hashes);

        co_await (ch2.send(hashes));

        setTimePoint("BOB : run-sendHash");
    }

    Proto RsPsi3rdPSenderB::runSpHshPsiOsn(Socket &chl, Socket &ch2, std::vector<block> &sendSet, std::vector<block> &payloadSet)
    {
        setTimePoint("BOB : enter protocol");
        setSenderSize(sendSet.size());
        co_await (ch2.send(sendSet.size()));

        co_await (runSpHshPSI(sendSet, chl, ch2));

        setTimePoint("BOB : PSI is done");

        co_await (ch2.recv(mCardinality));

        getOSNReceiver().init(sendSet.size(), 1);

        setTimePoint("BOB : before run_osn");

        co_await (getOSNReceiver().run_osn(payloadSet, ch2, mReceiver_shares));

        setTimePoint("BOB : after run_osn");

        mSenderA_shares.resize(mCardinality);
        co_await (ch2.recv(mSenderA_shares));
        setTimePoint("BOB : Receive shares from SHS");

        myPi_SdrB.resize(mCardinality);
        co_await (ch2.recv(myPi_SdrB));
    }

    task<> RsPsi3rdPSenderA::runSpHshPSI(span<block> inputs, Socket &chl, Socket &ch2)
    {

        auto data = std::unique_ptr<block[]>{};
        auto myHashes = span<block>{};
        auto psiSeed = block{};
        setTimePoint("ALICE : run-PSI begin");

        psiSeed = mSpH_prng.get();

        co_await (chl.send(psiSeed));
        data = std::unique_ptr<block[]>(new block[mRecverSize]);
        myHashes = span<block>(data.get(), mRecverSize);
        mAEShash.setKey(psiSeed);
        mAEShash.hashBlocks(inputs, myHashes);
        co_await (ch2.send(myHashes));

        setTimePoint("ALICE : run-sendHash");
        std::cout << "Alice sends to Bob: " << chl.bytesSent() << " Bytes." << std::endl;
    }

    Proto RsPsi3rdPSenderA::runSpHshPsiOsn(Socket &chl, Socket &ch2, std::vector<block> &recverSet, std::vector<block> &payloadSet)
    {
        setTimePoint("ALICE : enter protocol");
        setRecverSize(recverSet.size());
        initSpH_prng();
        co_await (ch2.send(recverSet.size()));

        co_await (runSpHshPSI(recverSet, chl, ch2));

        setTimePoint("ALICE : PSI is done");
        co_await (ch2.recv(mCardinality));
        getOSNReceiver().init(recverSet.size(), 1);

        setTimePoint("ALICE : before run_osn");

        co_await (getOSNReceiver().run_osn(payloadSet, ch2, mReceiver_shares));

        setTimePoint("ALICE : after run_osn");

        mSenderB_shares.resize(mCardinality);
        co_await (ch2.recv(mSenderB_shares));
        setTimePoint("ALICE : Receive shares from SHS");

        myPi_SdrA.resize(mCardinality);
        co_await (ch2.recv(myPi_SdrA));
    }

    task<> RsPsi3rdPReceiver::runSpHshPSI(Socket &chl, Socket &ch2)
    {
        auto data = std::unique_ptr<block[]>{};
        auto myHashes = span<block>{};
        auto theirHashes = span<block>{};
        auto map_hash = google::dense_hash_map<block, u64, NoHash>{};

        auto i = u64{};

        setTimePoint("SHS : run-PSI begin");
        mIntersectionA.clear();
        mIntersectionB.clear();
        data = std::unique_ptr<block[]>(new block[mSenderSize +
                                                  mRecverSize]);

        myHashes = span<block>(data.get(), mRecverSize);
        theirHashes = span<block>(data.get() + mRecverSize, mSenderSize);

        co_await (ch2.recv(myHashes));

        co_await (chl.recv(theirHashes));

        if (myHashes.size() != mRecverSize || theirHashes.size() != mSenderSize)
            throw RTE_LOC;

        map_hash.resize(myHashes.size());
        map_hash.set_empty_key(oc::ZeroBlock);
        for (i = 0; i < mRecverSize; i++)
        {
            map_hash.insert({myHashes[i], i});
        }

        {
            block h = oc::ZeroBlock;
            auto iter = theirHashes.data();

            for (i = 0; i < mSenderSize; ++i)
            {
                memcpy(&h, iter, 16);
                iter += 1;

                auto iter = map_hash.find(h);
                if (iter != map_hash.end())
                {
                    mIntersectionA.push_back(iter->second);
                    mIntersectionB.push_back(i);
                }
            }
        }
        setTimePoint("SHS : run-found");
    }

    task<> RsPsi3rdPReceiver::run_OSN_Ssingle(Socket &chl, OSNSender &OsnSender, std::vector<u64> intersection,
                                              size_t size, std::vector<block> &sender_shares)
    {
        std::vector<int> myPi;
        std::map<int, int> i2loc{};

        osuCrypto::Timer::timeUnit time_start, time_end;

        setTimePoint("SHS : enter OSN");

        setTimePoint("SHS : OSN begin");
        mCardinality = intersection.size();
        co_await (chl.send(intersection.size()));
        OsnSender.init_wj(size, 1, "benes", i2loc);
        setTimePoint("SHS : OSN init");
        myPi = OsnSender.getmyPi(i2loc, intersection);
        OsnSender.setPi(myPi);
        setTimePoint("SHS : get myPi");

        co_await (OsnSender.run_osn(chl, sender_shares));
    }

    Proto RsPsi3rdPReceiver::runSpHshPsiOsn(Socket &chl, Socket &ch2)
    {
        std::vector<int> myPiA, myPiB;
        std::vector<block> interPLA, interPLB;
        setTimePoint("SHS : enter protocol");

        co_await (macoro::when_all_ready(ch2.recv(mRecverSize), chl.recv(mSenderSize)));

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

        setTimePoint("SHS : osn shares sent to A B");

        co_await (macoro::when_all_ready(chl.send(std::move(myPiB)), ch2.send(std::move(myPiA))));
    }

}