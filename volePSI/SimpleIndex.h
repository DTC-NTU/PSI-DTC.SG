#pragma once

// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
