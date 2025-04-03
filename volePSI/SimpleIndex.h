#pragma once

#include "volePSI/Defines.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
namespace volePSI
{

    class SimpleIndex
    {
    public:
        struct Item
        {
            Item() : mVal(-1) {}

            Item &operator=(const Item &) = default;

            bool isEmpty() const { return mVal == u64(-1); }

            u64 idx() const { return mVal & (u64(-1) >> 8); }

            u64 hashIdx() const { return ((u8 *)&mVal)[7]; }

            void set(u64 idx, u8 hashIdx)
            {
                mVal = idx;
                ((u8 *)&mVal)[7] = hashIdx;
            }
#ifdef THREAD_SAFE_SIMPLE_INDEX
            Item(const Item &b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            Item(Item &&b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            std::atomic<u64> mVal;
#else
            Item(const Item &b) : mVal(b.mVal) {}
            Item(Item &&b) : mVal(b.mVal) {}
            u64 mVal;
#endif
        };

        u64 mMaxBinSize, mNumHashFunctions;

        Matrix<Item> mBins;
        u64 mNumBins;

        Matrix<u64> mItemToBinMap;

        std::vector<u64> mBinSizes;

        block mHashSeed;
        static u64 get_bin_size(u64 numBins, u64 numBalls, u64 statSecParam, bool approx = true);

        void init(u64 numBins, u64 numBalls, u64 statSecParam = 40, u64 numHashFunction = 3);
    };

}
