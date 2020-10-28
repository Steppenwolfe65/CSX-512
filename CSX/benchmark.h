/**
* \file symmetric_benchmark.h
* \brief <b>AES and RHX performance benchmarking</b> \n
* Tests the CBC, CTR, AND HBA modes for timimng performance.
* \author John Underhill
* \date October 12, 2020
*/

#ifndef QSCTEST_CIPHER_SPEED_H
#define QSCTEST_CIPHER_SPEED_H

#include "common.h"

/**
* \brief Tests the CSX implementations performance.
* Tests the CSX stream cipher for performance timing.
*/
void qsctest_csx_speed_run();

#endif