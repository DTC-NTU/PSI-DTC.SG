#pragma once
// © 2022 Visa.
// Modified version of original code by Visa
// © 2025 Digital Trust Centre - Nanyang Technological University. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "volePSI/Defines.h"
#include "sparsehash/dense_hash_map"
#include "cryptoTools/Common/Timer.h"
// *** tkl for osn
#include "osn/OSNReceiver.h"
#include "osn/OSNSender.h"
// *****
namespace volePSI
{
    namespace details
    {
        struct RsPsiBase
        {
            u64 mSenderSize = 0;
            u64 mRecverSize = 0;
            u64 mSsp = 0;
            PRNG mPrng;
            bool mMalicious = false;
            bool mCompress = true;
            u64 mNumThreads = 0;
            u64 mMaskSize = 0;
            bool mUseReducedRounds = false;
            bool mDebug = false;

            void init(u64 senderSize, u64 recverSize, u64 statSecParam, block seed, bool malicious, u64 numThreads, bool useReducedRounds = false);
            void setSenderSize(u64 senderSize) { mSenderSize = senderSize; };
            void setRecverSize(u64 recverSize) { mRecverSize = recverSize; };
            u64 getSenderSize() { return mSenderSize; }
            u64 getReceiverSize() { return mRecverSize; }
        };
    }

    // TKL added
    class RsPsi3rdPSenderA : public details::RsPsiBase, public oc::TimerAdapter
    {
        OSNReceiver mOsnRecv;
        std::vector<block> mReceiver_shares;
        std::vector<block> mSenderB_shares;
        size_t mCardinality = 0;
        PRNG mSpH_prng;
        std::vector<int> myPi_SdrA;
        size_t otherSetSize = 0;

    public:
        oc::AES mAEShash; // WJ: simple hash PSI.
        task<> run(span<block> inputs, Socket &chl, Socket &ch2);
        void initSpH_prng()
        {
            block seed = oc::sysRandomSeed();
            mSpH_prng.SetSeed(seed);
        } // WJ: simple hash PSI.
        task<> runSpHshPSI(span<block> inputs, Socket &ch1, Socket &ch2); // WJ: simple hash PSI.

        Proto runSpHshPsiOsn(Socket &chl, Socket &ch2, std::vector<block> &recvSet, std::vector<block> &payloadSet); // WJ : WJ: simple hash PSi with OSN
        OSNReceiver &getOSNReceiver() { return mOsnRecv; }
        std::vector<block> getSenderB_shares() { return mSenderB_shares; }
        std::vector<block> getReceiver_shares() { return mReceiver_shares; }
        size_t getCardinality() { return mCardinality; }
        std::vector<int> getmyPi() { return myPi_SdrA; }
    };

    class RsPsi3rdPSenderB : public details::RsPsiBase, public oc::TimerAdapter
    {
        OSNReceiver mOsnRecv;
        std::vector<block> mReceiver_shares;
        std::vector<block> mSenderA_shares;
        size_t mCardinality = 0;
        std::vector<int> myPi_SdrB;
        size_t otherSetSize = 0;

    public:
        oc::AES mAEShash;                                                 // WJ: simple hash PSI.
        task<> runSpHshPSI(span<block> inputs, Socket &ch1, Socket &ch2); // WJ: simple hash PSI.

        Proto runSpHshPsiOsn(Socket &chl, Socket &ch2, std::vector<block> &sendSet, std::vector<block> &payloadSet); // WJ : WJ: simple hash PSi with OSN
        OSNReceiver &getOSNReceiver() { return mOsnRecv; }
        std::vector<block> getSenderA_shares() { return mSenderA_shares; }
        std::vector<block> getReceiver_shares() { return mReceiver_shares; }
        size_t getCardinality() { return mCardinality; }
        std::vector<int> getmyPi() { return myPi_SdrB; }
    };

    class RsPsi3rdPReceiver : public details::RsPsiBase, public oc::TimerAdapter
    {
        OSNSender mOsnSenderA;
        OSNSender mOsnSenderB;
        std::vector<u64> mIntersectionA;
        std::vector<u64> mIntersectionB;
        std::vector<block> mSenderA_shares;
        std::vector<block> mSenderB_shares;
        size_t mCardinality = 0;

    public:
        std::vector<u64> getmIntersectionA() { return mIntersectionA; }
        std::vector<u64> getmIntersectionB() { return mIntersectionB; }
        //        void setmIntersectionB();   //WJ : for testing the getter error due to task<>
        task<> runSpHshPSI(Socket &ch1, Socket &ch2); // WJ: simple hash PSI.
        task<> run_OSN_Ssingle(Socket &chl, OSNSender &OsnSender, std::vector<u64> intersection,
                               size_t size, std::vector<block> &sender_shares);

        Proto runSpHshPsiOsn(Socket &chl, Socket &ch2); // WJ : WJ: simple hash PSi with OSN
        std::vector<int> getPermutationA() { return mOsnSenderA.dest; }
        std::vector<int> getPermutationB() { return mOsnSenderB.dest; }
        std::vector<int> getMyPi_A() { return mOsnSenderA.getPi(); }
        std::vector<int> getMyPi_B() { return mOsnSenderB.getPi(); }
        std::vector<block> getSenderA_shares() { return mSenderA_shares; }
        std::vector<block> getSenderB_shares() { return mSenderB_shares; }
        OSNSender &getOsnSenderA() { return mOsnSenderA; }
        OSNSender &getOsnSenderB() { return mOsnSenderB; }
        size_t getCardinality() { return mCardinality; }
        void myTimerPrinter(oc::Timer &mTimer); // WJ: to bemchmark AVERAGE time eclapse; to do: move into TimerAdapter
    };
}