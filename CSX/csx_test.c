/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2019 vtdev.com
* This file is part of the CEX Cryptographic library.
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* Test platform for the (CSX/RSX=eAES) symmetric block cipher.
* Contact: develop@vtdev.com */

#include "common.h"
#include "csx.h"
#include "csx_kat.h"
#include "sha3_kat.h"
#include <stdio.h>

/* AES-NI Detection */

#if defined(_MSC_VER)

#include <intrin.h>
#pragma intrinsic(__cpuid)

static int has_aes_ni()
{
	int32_t info[4];
	uint32_t mask;
	int32_t val;

	__cpuid(info, 1);

	if (info[2] != 0)
	{
		mask = (((1UL << 1) - 1) << 25);
		val = (((uint32_t)info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#elif defined(__GNUC__)

#include <cpuid.h>
#pragma GCC target ("ssse3")
#pragma GCC target ("sse4.1")
#pragma GCC target ("aes")
#include <x86intrin.h>

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	if (__get_cpuid(1, &info[0], &info[1], &info[2], &info[3]))
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#else

static int has_aes_ni()
{
	return 0;
}

#endif

void get_response()
{
	wint_t ret;

	ret = getwchar();
}

int main()
{
	int valid;

	valid = 1;

	if (has_aes_ni() == 1)
	{
		printf_s("AES-NI is available on this system. \n");
#if !defined(CSX_AESNI_ENABLED)
		printf_s("Add the CSX_AESNI_ENABLED flag to the preprocessor definitions to test AES-NI implementation. \n");
#else
		printf_s("The CSX_AESNI_ENABLED flag has been detected, AES-NI intrinsics are enabled. \n");
#endif
		printf_s("\n");
	}
	else
	{
		printf_s("AES-NI was not detected on this system. \n");
#if defined(CSX_AESNI_ENABLED)
		printf_s("Remove the CSX_AESNI_ENABLED flag from the preprocessor definitions to test the fallback implementation. \n");
		printf_s("Configuration settings error; AES-NI is enabled but not available on this system, check your compiler preprocessor settings. \n");
		printf_s("\n");
		valid = 0;
#endif
	}

	if (valid == 1)
	{
		printf_s("*** Test extended cipher implementations using Stress testing, Monte Carlo, and KAT vector tests from CEX++ *** \n");
		csx_run();
		printf_s("\n");

		printf_s("*** Test SHAKE, cSHAKE, KMAC, and SHA3 implementations using the official KAT vetors. *** \n");

		printf_s("Completed! Press any key to close..");
		get_response();
	}
	else
	{
		printf_s("The test has been cancelled. Press any key to close..");
		get_response();
	}

	return 0;
}

