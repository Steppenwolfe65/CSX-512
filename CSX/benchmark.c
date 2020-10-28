#include "benchmark.h"
#include "csp.h"
#include "csx.h"
#include "testutils.h"
#include "timer.h"

/* bs*sc = 1GB */
#define BUFFER_SIZE 1024
#define SAMPLE_COUNT 1000000
#define ONE_GIGABYTE 1024000000

static void csx_speed_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	qsc_csx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_csx_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_csx_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_csx_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("CSX-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

void qsctest_csx_speed_run()
{
	qsctest_print_line("Running the CSX-512 performance benchmarks.");
	csx_speed_test();
}

