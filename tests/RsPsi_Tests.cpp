#include "RsPsi_Tests.h"
#include "volePSI/RsPsi.h"
#include "volePSI/RsCpsi.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include <vector>
#include "Common.h"

using namespace oc;
using namespace volePSI;
using coproto::LocalAsyncSocket;
using namespace std;
namespace
{
    void myTimerPrinter(const Timer& timer)
    {
        if (timer.mTimes.size() > 1)
        {
            u64 maxStars = 10;
            u64 p = 9;
            u64 width = 0;
            auto maxLog = 1.0;

            {
                auto prev = timer.mTimes.begin();
                auto iter = timer.mTimes.begin(); ++iter;

                while (iter != timer.mTimes.end())
                {
                    width = std::max<u64>(width, iter->second.size());
                    auto diff = std::chrono::duration_cast<std::chrono::microseconds>(iter->first - prev->first).count() / 1000.0;
                    maxLog = std::max(maxLog, std::log2(diff));
                    ++iter;
                    ++prev;
                }
            }
            width += 3;


            std::cout << std::left<< std::setfill(' ') << std::setw(width) << "Label  " << "  " << std::setw(p) << "Time (ms)" << "  " << std::setw(p) << "diff (ms)\n__________________________________"  << std::endl;

            auto prev = timer.mTimes.begin();
            auto iter = timer.mTimes.begin(); ++iter;

            while (iter != timer.mTimes.end())
            {
                auto time = std::chrono::duration_cast<std::chrono::microseconds>(iter->first - timer.mTimes.front().first).count() / 1000.0;
                auto diff = std::chrono::duration_cast<std::chrono::microseconds>(iter->first - prev->first).count() / 1000.0;
                u64 numStars = static_cast<u64>(std::round(std::max(0.1, std::log2(diff)) * maxStars / maxLog));

                std::cout << std::setw(width) << std::left << iter->second
                    << "  " << std::right << std::fixed << std::setprecision(1) << std::setw(p) << time
                    << "  " << std::right << std::fixed << std::setprecision(3) << std::setw(p) << diff
                    << "  " << std::string(numStars, '*') << std::endl;;

                ++prev;
                ++iter;
            }
        }
    }
     void myAveTimerPrinter(const Timer & mTimer)  // WJ: To print AVERAGED diffs for benchmarkin purpose
    {
        auto timer = mTimer.mTimes;
        if (timer.size() > 1)
        {
            u64 maxStars = 10;
            u64 p = 9;
            u64 width = 0;
            auto maxLog = 1.0;

            {
                auto prev = timer.begin();
                auto iter = timer.begin();
                ++iter;

                while (iter != timer.end())
                {
                    width = std::max<u64>(width, iter->second.size());
                    auto diff = std::chrono::duration_cast<std::chrono::microseconds>(iter->first - prev->first).count() / 1000.0;
                    maxLog = std::max(maxLog, std::log2(diff));
                    ++iter;
                    ++prev;
                }
            }
            width += 3;

            auto prev = timer.begin();
            auto iter = timer.begin();
            ++iter;

            std::map<std::string, std::pair<double, u32>> steptime;
            std::vector<std::string> inserOrder;
            double total = std::chrono::duration_cast<std::chrono::microseconds>(timer.back().first - timer.front().first).count() / 1000.0;
            // std::map<std::string, u32> count;
            while (iter != timer.end())
            {
                auto time = std::chrono::duration_cast<std::chrono::microseconds>(iter->first - timer.front().first).count() / 1000.0;
                auto diff = std::chrono::duration_cast<std::chrono::microseconds>(iter->first - prev->first).count() / 1000.0;

                auto it = steptime.find(iter->second);

                if (it != steptime.end())
                {
                    it->second.first += diff;
                    it->second.second++;
                }
                else
                {
                    steptime[iter->second] = {diff, 1};
                    inserOrder.push_back(iter->second);
                }

                ++prev;
                ++iter;
            }
            
            std::cout << "\n"
                      << std::left << std::setfill(' ') << std::setw(width) << "Label  " 
                      << "  " << std::setw(p) << "Total Time (ms)"
                      << "  " << std::setw(p) << "AVG Time (ms)\n__________________________________" << std::endl;

            for (const auto &key : inserOrder)
            {
                // std::cout <<  << " ";
                std::cout << std::setw(width) << std::left << key
                          << "  " << std::right << std::fixed << std::setprecision(3) << std::setw(p) << steptime[key].first
                          << "  " << std::right << std::fixed << std::setprecision(3) << std::setw(p) << steptime[key].first / steptime[key].second
                          << std::endl;
            }
            std::cout << "Total time (ms): " << total << std::endl;
        }
    } 



    std::vector<u64> run(PRNG& prng, std::vector<block>& recvSet, std::vector<block> &sendSet, bool mal, u64 nt = 1, bool reduced = false)
    {
        auto sockets = LocalAsyncSocket::makePair();

        RsPsiReceiver recver;
        RsPsiSender sender;

        recver.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, nt, reduced);
        sender.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, nt, reduced);

        auto p0 = recver.run(recvSet, sockets[0]); 
        auto p1 = sender.run(sendSet, sockets[1]);

        eval(p0, p1);
        
        return recver.mIntersection;
    }

    std::vector<u64> run_osn(PRNG& prng, std::vector<block>& recvSet, std::vector<block> &sendSet, bool mal, u64 nt = 1, bool reduced = false)
    {
        auto sockets1 = LocalAsyncSocket::makePair();
        auto sockets2 = LocalAsyncSocket::makePair();
        auto sockets3 = LocalAsyncSocket::makePair();
        RsPsi3rdPReceiver recver;
        RsPsi3rdPSenderB senderB;
        RsPsi3rdPSenderA senderA;

        recver.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, nt, reduced);
        senderB.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, nt, reduced);        
        senderA.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, nt, reduced);
/*
        auto shs = recver.run_sockTest(sockets2[1], sockets3[1]); 
        auto p0 = senderB.run_sockTest(recvSet, sockets1[0], sockets2[0]); 
        auto p1 = senderA.run_sockTest(sendSet, sockets1[1], sockets3[0]); 
*/
        auto shs = recver.run(sockets3[1], sockets2[1]); 
        auto p0 = senderB.run(recvSet, sockets1[0], sockets3[0]); 
        auto p1 = senderA.run(sendSet, sockets1[1], sockets2[0]); 
        eval(shs, p0, p1);

        vector<block> sender_sharesA;
        vector<block> receiver_sharesA;
        vector<int> permutationA;
		OSNSender osnSender;

        vector<block> sender_sharesB;
        vector<block> receiver_sharesB;
        vector<int> permutationB;
		OSNReceiver osnRecvA;        
		OSNReceiver osnRecvB;
        std::vector<int> myPi_A;
        std::vector<int> myPi_B;
        std::map<int, int> i2loc{};

     //   mTimer.setTimePoint("Begin: OSN");
		osnSender.init_wj(sendSet.size(), 1,"benes", i2loc); // WJ: "benes" is needed to read from cache; in vs code debug mode. "benes" files is read from and save in the folder where init_wj is called.
        osnRecvA.init(sendSet.size(), 1);
        std::vector<u64> intersectionA =  recver.getmIntersectionA();
        myPi_A = osnSender.getmyPi(i2loc, intersectionA); // TKL  //WJ: i2loc is the \pi'' permutation in my implementation note slide 
		 shs = osnSender.run_osn(sockets2[1], sender_sharesA);		
		 p0 = osnRecvA.run_osn(sendSet, sockets2[0], receiver_sharesA);

        eval(shs, p0);
        permutationA = osnSender.dest;

        i2loc.clear();
		osnSender.init_wj(recvSet.size(), 1,"benes", i2loc); // WJ: "benes" is needed to read from cache;
        osnRecvB.init(recvSet.size(), 1);
        std::vector<u64> intersectionB =  recver.getmIntersectionB();
        myPi_B = osnSender.getmyPi(i2loc, intersectionB); // TKL

		 shs = osnSender.run_osn(sockets3[1], sender_sharesB);		
		 p1 = osnRecvB.run_osn(recvSet, sockets3[0], receiver_sharesB);

        eval(shs, p1);
        permutationB = osnSender.dest;

        int correct_cnt = 0;  
        for (auto i = 0; i < myPi_A.size(); i++)
        {
            // cout << i <<" sender_shares=" << sender_shares[i] << endl;
            // cout << i << " receiver_shares=" << receiver_shares[i] << endl;
            // cout << i << " permutationA=" << permutationA[i] << endl;
            // cout << " SetA["<< permutationA[i] << "] = " << SetA[permutationA[i]] << endl;
            auto j = myPi_A[i];
            block tmp = sender_sharesA[j] ^ receiver_sharesA[j];
        //  cout << " tmp=" << tmp << endl;
            if (tmp == sendSet[intersectionA[i]])
            {
                correct_cnt++;
            }
        }
    cout << "********** Size=" << intersectionA.size() << ", correct_cnt=" << correct_cnt << endl;

        correct_cnt = 0;
        for (auto i = 0; i < myPi_B.size(); i++)
        {
            // cout << i <<" sender_shares=" << sender_shares[i] << endl;
            // cout << i << " receiver_shares=" << receiver_shares[i] << endl;
            // cout << i << " permutationA=" << permutationA[i] << endl;
            // cout << " SetA["<< permutationA[i] << "] = " << SetA[permutationA[i]] << endl;
            auto j = myPi_B[i];
            block tmp = sender_sharesB[j] ^ receiver_sharesB[j];
        //  cout << " tmp=" << tmp << endl;
            if (tmp == recvSet[intersectionB[i]])
            {
                correct_cnt++;
            }
        }
    cout << "********** Size=" << intersectionB.size() << ", correct_cnt=" << correct_cnt << endl;
        return recver.getmIntersectionA();
    }

}

//WJ : Simple Hash PSI + OSN integrated
std::vector<u64> run_SpHshPsiOsn(PRNG& prng, std::vector<block>& recvSet, std::vector<block> &sendSet, oc::Timer & mTimer)
{
        auto sockets1 = LocalAsyncSocket::makePair();
        auto sockets2 = LocalAsyncSocket::makePair();
        auto sockets3 = LocalAsyncSocket::makePair();
        RsPsi3rdPReceiver recver;
        RsPsi3rdPSenderB senderB;
        RsPsi3rdPSenderA senderA;
        recver.setTimer(mTimer);
        if (recver.mTimer)
            recver.setTimer(recver.getTimer());
        recver.setTimePoint("SHS (out) : psiosn begin");

        auto shs = recver.runSpHshPsiOsn(sockets3[1], sockets2[1]);
        auto p0 = senderB.runSpHshPsiOsn(sockets1[1], sockets3[0], sendSet, sendSet);
        auto p1 = senderA.runSpHshPsiOsn(sockets1[0], sockets2[0], recvSet, recvSet);
        eval(shs, p0, p1);
        recver.setTimePoint("SHS (out) : psiosn end");
//        std::cout << "SHS sends to Bob: " << sockets3[1].bytesSent() << " Bytes, SHS sends to Alice  " << sockets2[1].bytesSent()<< " Bytes" << std::endl;
//        std::cout << "Bob sends to SHS" << sockets3[0].bytesSent() << " Bytes, ALice sends to SHS  "  << sockets2[0].bytesSent() <<   " Bytes" << std::endl;
        vector<block> recvSet_sharesA = senderA.getReceiver_shares();
        vector<block> sendSet_sharesA = senderA.getSenderB_shares();
        
        vector<block> sendSet_sharesB = senderB.getReceiver_shares();
        vector<block> recvSet_sharesB = senderB.getSenderA_shares();
       
        vector<int> permutationA = recver.getPermutationA();
        vector<int> permutationB = recver.getPermutationB();

        int correct_cnt = 0;
        for (auto i = 0; i < sendSet.size(); i++)
		{
			// cout << i <<" sender_shares=" << sender_shares[i] << endl;
			// cout << i << " receiver_shares=" << receiver_shares[i] << endl;
			// cout << i << " permutationA=" << permutationA[i] << endl;
			// cout << i << " sendSet=" << sendSet[permutationA[i]] << endl;
			block tmp = sendSet_sharesA[i] ^ sendSet_sharesB[i];
			// cout << i << " tmp=" << tmp << endl;
			if (tmp == sendSet[permutationB[i]])
			{
				correct_cnt++;
			}
		}
		cout << "********** size=" << sendSet.size() << ", correct_cnt=" << correct_cnt << endl;	

        correct_cnt = 0;
		for (auto i = 0; i < recvSet.size(); i++)
		{
			// cout << i <<" sender_shares=" << sender_shares[i] << endl;
			// cout << i << " receiver_shares=" << receiver_shares[i] << endl;
			// cout << i << " permutationB=" << permutationB[i] << endl;
			// cout << i << " recvSet=" << recvSet[permutationB[i]] << endl;
			block tmp = recvSet_sharesA[i] ^ recvSet_sharesB[i];
			// cout << i << " tmp=" << tmp << endl;
			if (tmp == recvSet[permutationA[i]])
			{
				correct_cnt++;
			}
		}
		cout << "********** size=" << recvSet.size() << ", correct_cnt=" << correct_cnt << endl;	

        return recver.getmIntersectionB();

}

std::vector<u64> run_PsiOsn(PRNG& prng, std::vector<block>& recvSet, std::vector<block> &sendSet, bool mal, oc::Timer & mTimer, u64 nt = 1, bool reduced = false)
    {
        auto sockets1 = LocalAsyncSocket::makePair();
        auto sockets2 = LocalAsyncSocket::makePair();
        auto sockets3 = LocalAsyncSocket::makePair();
        RsPsi3rdPReceiver recver;
        RsPsi3rdPSenderB senderB;
        RsPsi3rdPSenderA senderA;
    //    oc::Timer timerSHS, timerA, timerB;
        recver.setTimer(mTimer);
        //senderA.setTimer(mTimer);
        //senderB.setTimer(mTimer);
        if (recver.mTimer)
            recver.setTimer(recver.getTimer());
        //if (senderB.mTimer)
        //    senderB.setTimer(recver.getTimer());
        //if (senderA.mTimer)
        //    senderA.setTimer(recver.getTimer());
        recver.setTimePoint("SHS (out) : psiosn begin");

        // for (size_t i = 0; i < 2; i++)
        // {
        auto shs = recver.run_OSN_integrated(sockets3[1], sockets2[1], 40, prng.get(), mal, nt, reduced);
        auto p0 = senderB.run_OSN_integrated(sockets1[0], sockets3[0], recvSet, recvSet, recvSet.size(), 40, prng.get(), mal, nt, reduced);
        auto p1 = senderA.run_OSN_integrated(sockets1[1], sockets2[0], sendSet, sendSet, sendSet.size(), 40, prng.get(), mal, nt, reduced);
        eval(shs, p0, p1);
        // }

        recver.setTimePoint("SHS (out) : psiosn end");
        //std::cout << "-------------log--------------------\n" << std::endl;
        //std::cout << recver.getTimer() << std::endl;
       // std::cout << "-------------log for myTimerPrinter--------------------\n" << std::endl;
       // recver.myTimerPrinter(recver.getTimer());      
        vector<block> sender_sharesA = senderA.getReceiver_shares();
        vector<block> receiver_sharesA = senderA.getSenderB_shares();
        
        vector<block> sender_sharesB = senderB.getReceiver_shares();
        vector<block> receiver_sharesB = senderB.getSenderA_shares();
       
        vector<int> permutationA = recver.getPermutationA();
        vector<int> permutationB = recver.getPermutationB();

		int correct_cnt = 0;

		for (auto i = 0; i < sendSet.size(); i++)
		{
			// cout << i <<" sender_shares=" << sender_shares[i] << endl;
			// cout << i << " receiver_shares=" << receiver_shares[i] << endl;
			// cout << i << " permutationA=" << permutationA[i] << endl;
			// cout << i << " sendSet=" << sendSet[permutationA[i]] << endl;
			block tmp = sender_sharesA[i] ^ receiver_sharesB[i];
			// cout << i << " tmp=" << tmp << endl;
			if (tmp == sendSet[permutationA[i]])
			{
				correct_cnt++;
			}
		}
		cout << "********** size=" << sendSet.size() << ", correct_cnt=" << correct_cnt << endl;	

        correct_cnt = 0;
		for (auto i = 0; i < recvSet.size(); i++)
		{
			// cout << i <<" sender_shares=" << sender_shares[i] << endl;
			// cout << i << " receiver_shares=" << receiver_shares[i] << endl;
			// cout << i << " permutationB=" << permutationB[i] << endl;
			// cout << i << " recvSet=" << recvSet[permutationB[i]] << endl;
			block tmp = sender_sharesB[i] ^ receiver_sharesA[i];
			// cout << i << " tmp=" << tmp << endl;
			if (tmp == recvSet[permutationB[i]])
			{
				correct_cnt++;
			}
		}
		cout << "********** size=" << recvSet.size() << ", correct_cnt=" << correct_cnt << endl;	

        return recver.getmIntersectionA();
    }


void Psi_Rs_empty_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    auto inter = run(prng, recvSet, sendSet, false);

    if (inter.size())
        throw RTE_LOC;
}


void Psi_Rs_partial_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            recvSet[i] = sendSet[(i + 312) % n];
            exp.insert(i);
        }
    }

    auto inter = run(prng, recvSet, sendSet, false);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
    {
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act.size() << std::endl;
        throw RTE_LOC;
    }
}


void Psi_Rs_full_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    sendSet = recvSet;

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
        exp.insert(i);

    auto inter = run(prng, recvSet, sendSet, false);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}

//WJ : 3 Party Hash based PSI
std::vector<u64> runSpHsh(PRNG &prng, std::vector<block> &recvSet, std::vector<block> &sendSet, bool mal, oc::Timer & mTimer)
{
         auto sockets1 = LocalAsyncSocket::makePair();
        auto sockets2 = LocalAsyncSocket::makePair();
        auto sockets3 = LocalAsyncSocket::makePair(); 
        RsPsi3rdPReceiver recver;
        RsPsi3rdPSenderB senderB;
        RsPsi3rdPSenderA senderA;

        recver.setTimer(mTimer);
        if (recver.mTimer)
            recver.setTimer(recver.getTimer());
/*
        recver.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, 1, false);
        senderB.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, 1, false);        
        senderA.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, 1, false);
        senderA.initSpH_prng();
*/
        recver.setSenderSize(sendSet.size());
        recver.setRecverSize(recvSet.size());
        senderB.setSenderSize(sendSet.size());
        senderA.setRecverSize(recvSet.size());
        senderA.initSpH_prng();

        
        auto shs = recver.runSpHshPSI(sockets3[1], sockets2[1]);    // first socket to Bob; 2nd socket to Alice
        auto p0 = senderB.runSpHshPSI(sendSet, sockets1[1], sockets3[0]);  // first socket to Alice; 2nd socket to SHS
        auto p1 = senderA.runSpHshPSI(recvSet, sockets1[0], sockets2[0]);   // first socket to Bob; 2nd socket to SHS
        eval(shs, p0, p1);
 /*        std::cout << "Bob to SHS: " << sockets3[0].bytesSent() << " Bytes,\n"  << std::flush;
        std::cout << "Alice to SHS: " << sockets2[0].bytesSent() << " Bytes,\n"  << std::flush;
        std::cout << "Alice to Bob: " << sockets1[0].bytesSent() << " Bytes."  << std::endl; */

        return recver.getmIntersectionB();
}

void Psi_SpHsh_test(const oc::CLP& cmd)
{
    u64 n = cmd.getOr("n", 4194304);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    std::vector<u64> inter;
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    std::set<u64> exp;
    u64 t = 50;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            sendSet[i] = recvSet[(i + 312) % n];
            exp.insert(i);
        }
    };

    oc::Timer mTimer, mTimer2;
    int64_t accuEclps = 0;
    float averEclps = 0.0;
    auto Begin2 = mTimer2.setTimePoint("Begin");
    for (size_t i = 0; i < t; i++)
    {
        inter = runSpHsh(prng, recvSet, sendSet, false, mTimer);
    }
    auto End2 = mTimer2.setTimePoint("End");
    accuEclps = std::chrono::duration_cast<std::chrono::milliseconds>(End2 - Begin2).count();
    averEclps = (double) accuEclps / t;
    std::cout << "average SpHsh PSI eclapse = " <<  averEclps << "ms" << std::flush;
    std::cout << "total SpHsh PSI eclapse = " << accuEclps << "ms" <<  std::endl;

    //myTimerPrinter(mTimer);
    myAveTimerPrinter(mTimer);

    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}

//TKL 
void Psi_Rs_full_test_osn(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    sendSet = recvSet;

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
        exp.insert(i);

    auto inter = run_osn(prng, recvSet, sendSet, false);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}

void Psi_Rs_reduced_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    sendSet = recvSet;

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
        exp.insert(i);

    auto inter = run(prng, recvSet, sendSet, false, 1, true);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}


void Psi_Rs_multiThrd_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    u64 nt = cmd.getOr("nt", 8);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    sendSet = recvSet;

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
        exp.insert(i);

    auto inter = run(prng, recvSet, sendSet, false, nt);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}


void Psi_Rs_mal_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            recvSet[i] = sendSet[(i + 312) % n];
            exp.insert(i);
        }
    }

    auto inter = run(prng, recvSet, sendSet, true);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}

void Psi_Rs_mal_test_osn(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            recvSet[i] = sendSet[(i + 312) % n];
            exp.insert(i);
        }
    }
    auto inter = run(prng, recvSet, sendSet, true);
    std::set<u64> act(inter.begin(), inter.end());
    
    std::cout << "run(..) outcome " << std::endl;
    if (act != exp)
        throw RTE_LOC;

    inter = run_osn(prng, sendSet, recvSet, true);
    std::set<u64> act1(inter.begin(), inter.end());
    
    std::cout << "run_osn(..) outcome " << std::endl;
    if (act1 != exp)
        throw RTE_LOC;
}

void Psi_Rs_partial_test_osn(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 32); //13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            recvSet[i] = sendSet[(i + 312) % n];
            exp.insert(i);
        }
    }
    /* std::cout << "recvSet elements: ";
    for (const auto& element : recvSet) {
        std::cout << element << std::endl;
    }

    // Traverse and print the content of sendSet
    std::cout << "sendSet elements: ";
    for (const auto& element : sendSet) {
        std::cout << element << std::endl;
    }
 */
    auto inter = run(prng, recvSet, sendSet, false);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
    {
        std::cout << "run(..) outcome " << std::endl;
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act.size() << std::endl;
        throw RTE_LOC;
    }

    auto inter1 = run_osn(prng, sendSet, recvSet, false);
    std::set<u64> act1(inter1.begin(), inter1.end());
    if (act1 != exp)
    {
        std::cout << "run_osn(..) outcome " << std::endl;        
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act1.size() << std::endl;
        throw RTE_LOC;
    }
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act1.size() << std::endl;    
}

void Psi_SpHshPsiOsn_test_Integrated(const oc::CLP& cmd)
{
    u64 n = cmd.getOr("n", 262144);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());
    std::vector<u64> inter1;
    std::set<u64> exp;
    u64 t = 10;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            recvSet[i] = sendSet[(i + 312) % n];
            exp.insert(i);
        }
    }
    oc::Timer mTimer;
    for (size_t i = 0; i < t; i++)
    {
       inter1 = run_SpHshPsiOsn(prng, sendSet, recvSet, mTimer);
    }
    myTimerPrinter(mTimer);
    myAveTimerPrinter(mTimer);

    std::set<u64> act1(inter1.begin(), inter1.end());
    if (act1 != exp)
    {
        std::cout << "run_osn(..) outcome " << std::endl;        
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act1.size() << std::endl;
        throw RTE_LOC;
    }
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act1.size() << std::endl; 

}

void Psi_Rs_partial_test_osnIntegrated(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 32); //13243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());
    std::vector<u64> inter1;
    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            recvSet[i] = sendSet[(i + 312) % n];
            exp.insert(i);
        }
    }
    oc::Timer mTimer;
    for (size_t i = 0; i < 2; i++)
    {
       inter1 = run_PsiOsn(prng, sendSet, recvSet, false, mTimer);
    }
    myTimerPrinter(mTimer);
    std::set<u64> act1(inter1.begin(), inter1.end());
    if (act1 != exp)
    {
        std::cout << "run_osn(..) outcome " << std::endl;        
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act1.size() << std::endl;
        throw RTE_LOC;
    }
        std::cout << "exp size " << exp.size() << std::endl;
        std::cout << "act size " << act1.size() << std::endl;    
}

//WJ: test performance of osn unit
std::vector<int> getmyPi( const std::map<int, int> & i2loc, const std::vector<u64> & intersection )
{
    std::vector<int> myPi;
    //myPi.resize(intersection.size());
    for (u64 i = 0; i < intersection.size(); i++) // WJ: generate myPi to contain the positions where the intersections locate
    {
        auto iter = i2loc.find(intersection[i]);
        if (iter != i2loc.end())
        {
            //            std::cout << "i = " << i << ", intersection[i] = " << intersection[i] << ", "
            //                      << "i2loc[" << iter->first << " ]" << iter->second << std::endl;
            myPi.push_back(iter->second);
        }
        else
        {

            std::cout << "i2loc misses an intersection" << std::endl;
        }
    }
    return myPi;
}
void unit_test_osn(const CLP& cmd)
{
    oc::Timer mTimer;//, s, r;
    u64 t = 10;
    u64 n = cmd.getOr("n", 1048576);
    std::vector<block> SetA(n);
    std::vector<block> SetB(n);
    PRNG prng(ZeroBlock);
    mTimer.setTimePoint("OSN begin");
    prng.get(SetA.data(), SetA.size());
    prng.get(SetB.data(), SetB.size());
    std::vector<u64> intersection;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            SetA[i] = SetB[(i + 312) % n];
            intersection.push_back(i);
        }
    }
    mTimer.setTimePoint("generate 2 sets");
    auto socket = LocalAsyncSocket::makePair();
    OSNReceiver osnRecvA;
    OSNSender osnSender;

    vector<block> sender_sharesA;
    vector<block> receiver_sharesA;
    vector<int> permutationA;
    float averEclps = 0.0;
    int64_t accuEclps = 0;
    std::vector<int> myPi;
    std::map<int, int> i2loc{};

 //   mTimer.setTimePoint("Begin: OSN");
    osnSender.init_wj(SetA.size(), 1, "benes", i2loc); // WJ: "benes" is needed to read from cache;
    mTimer.setTimePoint("SHS OSN init");
    osnRecvA.init(SetA.size(), 1);                                  // 0： silent OT; 1: random OT
    mTimer.setTimePoint("Alice OSN init");

    myPi = getmyPi(i2loc, intersection);

    mTimer.setTimePoint("SHS generate permutation myPi");

    //   osnSender.setTimer(s);
    //   osnRecvA.setTimer(r);
	for (u64 i = 0; i < t; ++i)
	{
        sender_sharesA.clear();
        receiver_sharesA.clear(); //clear; otherwise influence run_osn
        mTimer.setTimePoint("clear shares");
        auto shs = osnSender.run_osn(socket[1], sender_sharesA);
        auto p0 = osnRecvA.run_osn(SetA, socket[0], receiver_sharesA);

 //       s.setTimePoint("Begin");
 //       r.setTimePoint("Begin");
        auto Begin = mTimer.setTimePoint("Begin");
        eval(shs, p0);
        mTimer.setTimePoint("Run OSN");
        auto End = mTimer.setTimePoint("End");
        accuEclps += std::chrono::duration_cast<std::chrono::milliseconds>(End - Begin).count();
    }
    averEclps = (double) accuEclps / t;
   
    std::cout << "-------------log--------------------\n" << std::endl;
    std::cout << "average OSN eclapse = " <<  averEclps << "ms" << std::endl;
    std::cout << "testing repeations = " << t << std::endl;
    std::cout << mTimer << std::endl;
    std::cout << "SHS sends: " << socket[1].bytesSent() /t << " Bytes, Alice sends " << socket[0].bytesSent() /t << " Bytes" << std::endl;

    int correct_cnt = 0;  
    for (auto i = 0; i < myPi.size(); i++)
    {
        // cout << i <<" sender_shares=" << sender_shares[i] << endl;
        // cout << i << " receiver_shares=" << receiver_shares[i] << endl;
        // cout << i << " permutationA=" << permutationA[i] << endl;
        // cout << " SetA["<< permutationA[i] << "] = " << SetA[permutationA[i]] << endl;
        auto j = myPi[i];
        block tmp = sender_sharesA[j] ^ receiver_sharesA[j];
       //  cout << " tmp=" << tmp << endl;
        if (tmp == SetA[intersection[i]])
        {
            correct_cnt++;
        }
    }
    cout << "********** size=" << intersection.size() << ", correct_cnt=" << correct_cnt << endl;
    
}