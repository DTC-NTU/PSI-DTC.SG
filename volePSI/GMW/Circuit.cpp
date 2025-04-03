#include "Circuit.h"
#include <string>
namespace volePSI
{

    BetaCircuit isZeroCircuit(u64 bits)
    {
        BetaCircuit cd;

        BetaBundle a(bits);

        cd.addInputBundle(a);

        // for (u64 i = 1; i < bits; ++i)
        //     cd.addGate(a.mWires[i], a.mWires[i], oc::GateType::Nxor, a.mWires[i]);
        auto ts = [](int s)
        { return std::to_string(s); };
        u64 step = 1;

        for (u64 i = 0; i < bits; ++i)
            cd.addInvert(a[i]);

        while (step < bits)
        {
            // std::cout << "\n step " << step << std::endl;
            cd.addPrint("\n step " + ts(step) + "\n");
            for (u64 i = 0; i + step < bits; i += step * 2)
            {
                cd.addPrint("a[" + ts(i) + "] & a[" + ts(i + step) + "] -> a[" + ts(i) + "]\n");
                cd.addPrint(a.mWires[i]);
                cd.addPrint(" & ");
                cd.addPrint(a.mWires[i + step]);
                cd.addPrint(" -> ");
                cd.addPrint(a.mWires[i]);
                // cd.addPrint("a[" + ts(i)+ "] &= a[" +ts(i + step) + "]\n");

                // std::cout << "a[" << i << "] &= a[" << (i + step) << "]" << std::endl;
                cd.addGate(a.mWires[i], a.mWires[i + step], oc::GateType::And, a.mWires[i]);
            }

            step *= 2;
        }
        // cd.addOutputBundle()
        a.mWires.resize(1);
        cd.mOutputs.push_back(a);

        cd.levelByAndDepth();

        return cd;
    }

}