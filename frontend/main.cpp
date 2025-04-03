#include "volePSI/fileBased.h"

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv);

    volePSI::doFileSpHshPSIwithOSN(cmd);

    return 0;
}