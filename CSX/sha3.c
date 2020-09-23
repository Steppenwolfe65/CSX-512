#include "sha3.h"
#include "intutils.h"
#include "memutils.h"

#define KECCAK_CSHAKE_DOMAIN_ID 0x04
#define KECCAK_KMAC_DOMAIN_ID 0x04
#define KECCAK_PERMUTATION_ROUNDS 24
#define KECCAK_SHA3_DOMAIN_ID 0x06
#define KECCAK_SHAKE_DOMAIN_ID 0x1F
#define KECCAK_STATE_BYTE_SIZE 200

/* keccak */

static void keccak_absorb(uint64_t* state, keccak_rate rate, const uint8_t* input, size_t inplen, uint8_t domain)
{
	uint8_t msg[QSC_KECCAK_STATE_BYTE_SIZE];

	while (inplen >= (size_t)rate)
	{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_xor((uint8_t*)state, input, rate);
#else
		for (size_t i = 0; i < rate / sizeof(uint64_t); ++i)
		{
			state[i] ^= qsc_intutils_le8to64(input + (sizeof(uint64_t) * i));
		}
#endif
		qsc_keccak_permute(state);
		inplen -= rate;
		input += rate;
	}

	qsc_memutils_copy(msg, input, inplen);
	msg[inplen] = domain;
	qsc_memutils_clear(msg + inplen + 1, rate - inplen + 1);
	msg[rate - 1] |= 128U;

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_xor((uint8_t*)state, msg, rate);
#else
	for (size_t i = 0; i < rate / 8; ++i)
	{
		state[i] ^= qsc_intutils_le8to64(msg + (8 * i));
	}
#endif
}

static void keccak_fast_absorb(uint64_t* state, const uint8_t* input, size_t inplen)
{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_xor((uint8_t*)state, input, inplen);
#else
	for (size_t i = 0; i < inplen / sizeof(uint64_t); ++i)
	{
		state[i] ^= qsc_intutils_le8to64(input + (sizeof(uint64_t) * i));
	}
#endif
}

static size_t keccak_left_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) 
	{
	}

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		buffer[i] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[0] = (uint8_t)n;

	return (size_t)n + 1;
}

static size_t keccak_right_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) 
	{
	}

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		buffer[i - 1] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[n] = (uint8_t)n;

	return (size_t)n + 1;
}

static void keccak_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks, keccak_rate rate)
{
	while (nblocks > 0)
	{
		qsc_keccak_permute(state);

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_copy(output, (uint8_t*)state, rate);
#else
		for (size_t i = 0; i < (rate >> 3); ++i)
		{
			qsc_intutils_le64to8(output + sizeof(uint64_t) * i, state[i]);
		}
#endif
		output += rate;
		nblocks--;
	}
}

static void keccak_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (msglen != 0)
	{
		if (ctx->position != 0 && (ctx->position + msglen >= (size_t)rate))
		{
			const size_t RMDLEN = rate - ctx->position;

			if (RMDLEN != 0)
			{
				qsc_memutils_copy(ctx->buffer + ctx->position, message, RMDLEN);
			}

			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			qsc_keccak_permute(ctx->state);
			ctx->position = 0;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= (size_t)rate)
		{
			keccak_fast_absorb(ctx->state, message, rate);
			qsc_keccak_permute(ctx->state);
			message += rate;
			msglen -= rate;
		}

		/* store unaligned bytes */
		if (msglen != 0)
		{
			qsc_memutils_copy(ctx->buffer + ctx->position, message, msglen);
			ctx->position += msglen;
		}
	}
}

#ifdef QSC_KECCAK_COMPACT_PERMUTATION

/* keccak round constants */
static const uint64_t KeccakF_RoundConstants[KECCAK_PERMUTATION_ROUNDS] =
{
	0x0000000000000001ULL,
	0x0000000000008082ULL,
	0x800000000000808aULL,
	0x8000000080008000ULL,
	0x000000000000808bULL,
	0x0000000080000001ULL,
	0x8000000080008081ULL,
	0x8000000000008009ULL,
	0x000000000000008aULL,
	0x0000000000000088ULL,
	0x0000000080008009ULL,
	0x000000008000000aULL,
	0x000000008000808bULL,
	0x800000000000008bULL,
	0x8000000000008089ULL,
	0x8000000000008003ULL,
	0x8000000000008002ULL,
	0x8000000000000080ULL,
	0x000000000000800aULL,
	0x800000008000000aULL,
	0x8000000080008081ULL,
	0x8000000000008080ULL,
	0x0000000080000001ULL,
	0x8000000080008008ULL
};

void qsc_keccak_permute(uint64_t* state)
{
	uint64_t Aba; 
	uint64_t Abe; 
	uint64_t Abi; 
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga; 
	uint64_t Age; 
	uint64_t Agi; 
	uint64_t Ago; 
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake; 
	uint64_t Aki; 
	uint64_t Ako; 
	uint64_t Aku;
	uint64_t Ama; 
	uint64_t Ame; 
	uint64_t Ami; 
	uint64_t Amo; 
	uint64_t Amu;
	uint64_t Asa; 
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso; 
	uint64_t Asu;
	uint64_t BCa; 
	uint64_t BCe; 
	uint64_t BCi; 
	uint64_t BCo; 
	uint64_t BCu;
	uint64_t Da;
	uint64_t De; 
	uint64_t Di; 
	uint64_t Do; 
	uint64_t Du;
	uint64_t Eba; 
	uint64_t Ebe; 
	uint64_t Ebi; 
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi; 
	uint64_t Ego; 
	uint64_t Egu;
	uint64_t Eka; 
	uint64_t Eke; 
	uint64_t Eki;
	uint64_t Eko; 
	uint64_t Eku;
	uint64_t Ema; 
	uint64_t Eme; 
	uint64_t Emi; 
	uint64_t Emo; 
	uint64_t Emu;
	uint64_t Esa; 
	uint64_t Ese; 
	uint64_t Esi;
	uint64_t Eso; 
	uint64_t Esu;
	size_t i;

	/* copyFromState(A, state) */
	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	for (i = 0; i < KECCAK_PERMUTATION_ROUNDS; i += 2)
	{
		/* prepareTheta */
		BCa = Aba ^ Aga^Aka^Ama^Asa;
		BCe = Abe ^ Age^Ake^Ame^Ase;
		BCi = Abi ^ Agi^Aki^Ami^Asi;
		BCo = Abo ^ Ago^Ako^Amo^Aso;
		BCu = Abu ^ Agu^Aku^Amu^Asu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ qsc_intutils_rotl64(BCe, 1);
		De = BCa ^ qsc_intutils_rotl64(BCi, 1);
		Di = BCe ^ qsc_intutils_rotl64(BCo, 1);
		Do = BCi ^ qsc_intutils_rotl64(BCu, 1);
		Du = BCo ^ qsc_intutils_rotl64(BCa, 1);

		Aba ^= Da;
		BCa = Aba;
		Age ^= De;
		BCe = qsc_intutils_rotl64(Age, 44);
		Aki ^= Di;
		BCi = qsc_intutils_rotl64(Aki, 43);
		Amo ^= Do;
		BCo = qsc_intutils_rotl64(Amo, 21);
		Asu ^= Du;
		BCu = qsc_intutils_rotl64(Asu, 14);
		Eba = BCa ^ ((~BCe)&  BCi);
		Eba ^= KeccakF_RoundConstants[i];
		Ebe = BCe ^ ((~BCi)&  BCo);
		Ebi = BCi ^ ((~BCo)&  BCu);
		Ebo = BCo ^ ((~BCu)&  BCa);
		Ebu = BCu ^ ((~BCa)&  BCe);

		Abo ^= Do;
		BCa = qsc_intutils_rotl64(Abo, 28);
		Agu ^= Du;
		BCe = qsc_intutils_rotl64(Agu, 20);
		Aka ^= Da;
		BCi = qsc_intutils_rotl64(Aka, 3);
		Ame ^= De;
		BCo = qsc_intutils_rotl64(Ame, 45);
		Asi ^= Di;
		BCu = qsc_intutils_rotl64(Asi, 61);
		Ega = BCa ^ ((~BCe)&  BCi);
		Ege = BCe ^ ((~BCi)&  BCo);
		Egi = BCi ^ ((~BCo)&  BCu);
		Ego = BCo ^ ((~BCu)&  BCa);
		Egu = BCu ^ ((~BCa)&  BCe);

		Abe ^= De;
		BCa = qsc_intutils_rotl64(Abe, 1);
		Agi ^= Di;
		BCe = qsc_intutils_rotl64(Agi, 6);
		Ako ^= Do;
		BCi = qsc_intutils_rotl64(Ako, 25);
		Amu ^= Du;
		BCo = qsc_intutils_rotl64(Amu, 8);
		Asa ^= Da;
		BCu = qsc_intutils_rotl64(Asa, 18);
		Eka = BCa ^ ((~BCe)&  BCi);
		Eke = BCe ^ ((~BCi)&  BCo);
		Eki = BCi ^ ((~BCo)&  BCu);
		Eko = BCo ^ ((~BCu)&  BCa);
		Eku = BCu ^ ((~BCa)&  BCe);

		Abu ^= Du;
		BCa = qsc_intutils_rotl64(Abu, 27);
		Aga ^= Da;
		BCe = qsc_intutils_rotl64(Aga, 36);
		Ake ^= De;
		BCi = qsc_intutils_rotl64(Ake, 10);
		Ami ^= Di;
		BCo = qsc_intutils_rotl64(Ami, 15);
		Aso ^= Do;
		BCu = qsc_intutils_rotl64(Aso, 56);
		Ema = BCa ^ ((~BCe)&  BCi);
		Eme = BCe ^ ((~BCi)&  BCo);
		Emi = BCi ^ ((~BCo)&  BCu);
		Emo = BCo ^ ((~BCu)&  BCa);
		Emu = BCu ^ ((~BCa)&  BCe);

		Abi ^= Di;
		BCa = qsc_intutils_rotl64(Abi, 62);
		Ago ^= Do;
		BCe = qsc_intutils_rotl64(Ago, 55);
		Aku ^= Du;
		BCi = qsc_intutils_rotl64(Aku, 39);
		Ama ^= Da;
		BCo = qsc_intutils_rotl64(Ama, 41);
		Ase ^= De;
		BCu = qsc_intutils_rotl64(Ase, 2);
		Esa = BCa ^ ((~BCe)&  BCi);
		Ese = BCe ^ ((~BCi)&  BCo);
		Esi = BCi ^ ((~BCo)&  BCu);
		Eso = BCo ^ ((~BCu)&  BCa);
		Esu = BCu ^ ((~BCa)&  BCe);

		/* prepareTheta */
		BCa = Eba ^ Ega^Eka^Ema^Esa;
		BCe = Ebe ^ Ege^Eke^Eme^Ese;
		BCi = Ebi ^ Egi^Eki^Emi^Esi;
		BCo = Ebo ^ Ego^Eko^Emo^Eso;
		BCu = Ebu ^ Egu^Eku^Emu^Esu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ qsc_intutils_rotl64(BCe, 1);
		De = BCa ^ qsc_intutils_rotl64(BCi, 1);
		Di = BCe ^ qsc_intutils_rotl64(BCo, 1);
		Do = BCi ^ qsc_intutils_rotl64(BCu, 1);
		Du = BCo ^ qsc_intutils_rotl64(BCa, 1);

		Eba ^= Da;
		BCa = Eba;
		Ege ^= De;
		BCe = qsc_intutils_rotl64(Ege, 44);
		Eki ^= Di;
		BCi = qsc_intutils_rotl64(Eki, 43);
		Emo ^= Do;
		BCo = qsc_intutils_rotl64(Emo, 21);
		Esu ^= Du;
		BCu = qsc_intutils_rotl64(Esu, 14);
		Aba = BCa ^ ((~BCe)&  BCi);
		Aba ^= KeccakF_RoundConstants[i + 1];
		Abe = BCe ^ ((~BCi)&  BCo);
		Abi = BCi ^ ((~BCo)&  BCu);
		Abo = BCo ^ ((~BCu)&  BCa);
		Abu = BCu ^ ((~BCa)&  BCe);

		Ebo ^= Do;
		BCa = qsc_intutils_rotl64(Ebo, 28);
		Egu ^= Du;
		BCe = qsc_intutils_rotl64(Egu, 20);
		Eka ^= Da;
		BCi = qsc_intutils_rotl64(Eka, 3);
		Eme ^= De;
		BCo = qsc_intutils_rotl64(Eme, 45);
		Esi ^= Di;
		BCu = qsc_intutils_rotl64(Esi, 61);
		Aga = BCa ^ ((~BCe)&  BCi);
		Age = BCe ^ ((~BCi)&  BCo);
		Agi = BCi ^ ((~BCo)&  BCu);
		Ago = BCo ^ ((~BCu)&  BCa);
		Agu = BCu ^ ((~BCa)&  BCe);

		Ebe ^= De;
		BCa = qsc_intutils_rotl64(Ebe, 1);
		Egi ^= Di;
		BCe = qsc_intutils_rotl64(Egi, 6);
		Eko ^= Do;
		BCi = qsc_intutils_rotl64(Eko, 25);
		Emu ^= Du;
		BCo = qsc_intutils_rotl64(Emu, 8);
		Esa ^= Da;
		BCu = qsc_intutils_rotl64(Esa, 18);
		Aka = BCa ^ ((~BCe)&  BCi);
		Ake = BCe ^ ((~BCi)&  BCo);
		Aki = BCi ^ ((~BCo)&  BCu);
		Ako = BCo ^ ((~BCu)&  BCa);
		Aku = BCu ^ ((~BCa)&  BCe);

		Ebu ^= Du;
		BCa = qsc_intutils_rotl64(Ebu, 27);
		Ega ^= Da;
		BCe = qsc_intutils_rotl64(Ega, 36);
		Eke ^= De;
		BCi = qsc_intutils_rotl64(Eke, 10);
		Emi ^= Di;
		BCo = qsc_intutils_rotl64(Emi, 15);
		Eso ^= Do;
		BCu = qsc_intutils_rotl64(Eso, 56);
		Ama = BCa ^ ((~BCe)&  BCi);
		Ame = BCe ^ ((~BCi)&  BCo);
		Ami = BCi ^ ((~BCo)&  BCu);
		Amo = BCo ^ ((~BCu)&  BCa);
		Amu = BCu ^ ((~BCa)&  BCe);

		Ebi ^= Di;
		BCa = qsc_intutils_rotl64(Ebi, 62);
		Ego ^= Do;
		BCe = qsc_intutils_rotl64(Ego, 55);
		Eku ^= Du;
		BCi = qsc_intutils_rotl64(Eku, 39);
		Ema ^= Da;
		BCo = qsc_intutils_rotl64(Ema, 41);
		Ese ^= De;
		BCu = qsc_intutils_rotl64(Ese, 2);
		Asa = BCa ^ ((~BCe)&  BCi);
		Ase = BCe ^ ((~BCi)&  BCo);
		Asi = BCi ^ ((~BCo)&  BCu);
		Aso = BCo ^ ((~BCu)&  BCa);
		Asu = BCu ^ ((~BCa)&  BCe);
	}

	/* copy to state */
	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

#else

void qsc_keccak_permute(uint64_t* state)
{
	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t Ca;
	uint64_t Ce;
	uint64_t Ci;
	uint64_t Co;
	uint64_t Cu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	/* round 1 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000000000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 2 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000008082ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 3 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x800000000000808AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 4 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008000ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 5 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 6 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000080000001ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 7 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 8 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008009ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 9 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000008AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 10 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000000088ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 11 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080008009ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 12 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x000000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 13 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000008000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 14 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000000000008BULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 15 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008089ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 16 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008003ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 17 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008002ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 18 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000000080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 19 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000800AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 20 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 21 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 22 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 23 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 24 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008008ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);

	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

#endif

/* common */

QSC_SYSTEM_OPTIMIZE_IGNORE
void qsc_keccak_dispose(qsc_keccak_state* ctx)
{
	if (ctx != NULL)
	{
		qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0;
	}
}
QSC_SYSTEM_OPTIMIZE_RESUME

/* sha3 */

void qsc_sha3_compute256(uint8_t* output, const uint8_t* message, size_t msglen)
{
	assert(output != NULL);
	assert(message != NULL);

	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_256_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	keccak_absorb(ctx.state, keccak_rate_256, message, msglen, KECCAK_SHA3_DOMAIN_ID);
	keccak_squeezeblocks(ctx.state, hash, 1, keccak_rate_256);
	qsc_memutils_copy(output, hash, QSC_SHA3_256_HASH_SIZE);
	qsc_keccak_dispose(&ctx);
}

void qsc_sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen)
{
	assert(output != NULL);
	assert(message != NULL);

	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_512_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	keccak_absorb(ctx.state, keccak_rate_512, message, msglen, KECCAK_SHA3_DOMAIN_ID);
	keccak_squeezeblocks(ctx.state, hash, 1, keccak_rate_512);
	qsc_memutils_copy(output, hash, QSC_SHA3_512_HASH_SIZE);
	qsc_keccak_dispose(&ctx);
}

void qsc_sha3_finalize(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	size_t hlen;

	hlen = (((QSC_KECCAK_STATE_SIZE * sizeof(uint64_t)) - rate) / 2);
	qsc_memutils_clear(ctx->buffer + ctx->position, sizeof(ctx->buffer) - ctx->position);
	ctx->buffer[ctx->position] = KECCAK_SHA3_DOMAIN_ID;
	ctx->buffer[rate - 1] |= 128U;
	keccak_fast_absorb(ctx->state, ctx->buffer, rate);
	qsc_keccak_permute(ctx->state);

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy(output, (uint8_t*)ctx->state, hlen);
#else

	for (size_t i = 0; i < hlen / sizeof(uint64_t); ++i)
	{
		qsc_intutils_le64to8(output, ctx->state[i]);
		output += sizeof(uint64_t);
	}
#endif

	qsc_keccak_dispose(ctx);
}

void qsc_sha3_initialize(qsc_keccak_state* ctx)
{
	qsc_keccak_dispose(ctx);
}

void qsc_sha3_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen)
{
	keccak_update(ctx, rate, message, msglen);
}

/* shake */

void qsc_shake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_128_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_128_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_shake_initialize(&ctx, keccak_rate_128, key, keylen);
	qsc_shake_squeezeblocks(&ctx, keccak_rate_128, output, nblocks);
	output += (nblocks * QSC_KECCAK_128_RATE);
	outlen -= (nblocks * QSC_KECCAK_128_RATE);

	if (outlen != 0)
	{
		qsc_shake_squeezeblocks(&ctx, keccak_rate_128, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_shake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_256_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_256_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_shake_initialize(&ctx, keccak_rate_256, key, keylen);
	qsc_shake_squeezeblocks(&ctx, keccak_rate_256, output, nblocks);
	output += (nblocks * QSC_KECCAK_256_RATE);
	outlen -= (nblocks * QSC_KECCAK_256_RATE);

	if (outlen != 0)
	{
		qsc_shake_squeezeblocks(&ctx, keccak_rate_256, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_shake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_512_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_512_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_shake_initialize(&ctx, keccak_rate_512, key, keylen);
	qsc_shake_squeezeblocks(&ctx, keccak_rate_512, output, nblocks);
	output += (nblocks * QSC_KECCAK_512_RATE);
	outlen -= (nblocks * QSC_KECCAK_512_RATE);

	if (outlen != 0)
	{
		qsc_shake_squeezeblocks(&ctx, keccak_rate_512, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_shake_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	keccak_absorb(ctx->state, rate, key, keylen, KECCAK_SHAKE_DOMAIN_ID);
}

void qsc_shake_squeezeblocks(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks)
{
	assert(ctx != NULL);
	assert(output != NULL);

	keccak_squeezeblocks(ctx->state, output, nblocks, rate);
}

/* cshake */

void qsc_cshake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_128_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_128_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));

	if (custlen + namelen != 0)
	{
		qsc_cshake_initialize(&ctx, keccak_rate_128, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		qsc_shake_initialize(&ctx, keccak_rate_128, key, keylen);
	}

	qsc_cshake_squeezeblocks(&ctx, keccak_rate_128, output, nblocks);
	output += (nblocks * QSC_KECCAK_128_RATE);
	outlen -= (nblocks * QSC_KECCAK_128_RATE);

	if (outlen != 0)
	{
		qsc_cshake_squeezeblocks(&ctx, keccak_rate_128, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_cshake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_256_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_256_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));

	if (custlen + namelen != 0)
	{
		qsc_cshake_initialize(&ctx, keccak_rate_256, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		qsc_shake_initialize(&ctx, keccak_rate_256, key, keylen);
	}

	qsc_cshake_squeezeblocks(&ctx, keccak_rate_256, output, nblocks);

	output += (nblocks * QSC_KECCAK_256_RATE);
	outlen -= (nblocks * QSC_KECCAK_256_RATE);

	if (outlen != 0)
	{
		qsc_cshake_squeezeblocks(&ctx, keccak_rate_256, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_cshake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_512_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_512_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));

	if (custlen + namelen != 0)
	{
		qsc_cshake_initialize(&ctx, keccak_rate_512, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		qsc_shake_initialize(&ctx, keccak_rate_512, key, keylen);
	}

	qsc_cshake_squeezeblocks(&ctx, keccak_rate_512, output, nblocks);
	output += (nblocks * QSC_KECCAK_512_RATE);
	outlen -= (nblocks * QSC_KECCAK_512_RATE);

	if (outlen != 0)
	{
		qsc_cshake_squeezeblocks(&ctx, keccak_rate_512, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_cshake_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint8_t pad[KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t i;
	size_t oft;

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode(pad + oft, namelen * 8);

	if (namelen != 0)
	{
		for (i = 0; i < namelen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				qsc_keccak_permute(ctx->state);
				oft = 0;
			}

			pad[oft] = name[i];
			++oft;
		}
	}

	oft += keccak_left_encode(pad + oft, custlen * 8);

	if (custlen != 0)
	{
		for (i = 0; i < custlen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				qsc_keccak_permute(ctx->state);
				oft = 0;
			}

			pad[oft] = custom[i];
			++oft;
		}
	}

	qsc_memutils_clear(pad + oft, rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	qsc_keccak_permute(ctx->state);

	/* initialize the key */
	keccak_absorb(ctx->state, rate, key, keylen, KECCAK_CSHAKE_DOMAIN_ID);
}

void qsc_cshake_squeezeblocks(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks)
{
	assert(ctx != NULL);
	assert(output != NULL);

	keccak_squeezeblocks(ctx->state, output, nblocks, (size_t)rate);
}

void qsc_cshake_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen)
{
	while (keylen >= (size_t)rate)
	{
		keccak_fast_absorb(ctx->state, key, keylen);
		qsc_keccak_permute(ctx->state);
		keylen -= rate;
		key += rate;
	}

	if (keylen != 0)
	{
		keccak_fast_absorb(ctx->state, key, keylen);
		qsc_keccak_permute(ctx->state);
	}
}

/* kmac */

void qsc_kmac128_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	qsc_keccak_state ctx;

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_kmac_initialize(&ctx, keccak_rate_128, key, keylen, custom, custlen);
	qsc_kmac_update(&ctx, keccak_rate_128, message, msglen);
	qsc_kmac_finalize(&ctx, keccak_rate_128, output, outlen);
}

void qsc_kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	qsc_keccak_state ctx;

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_kmac_initialize(&ctx, keccak_rate_256, key, keylen, custom, custlen);
	qsc_kmac_update(&ctx, keccak_rate_256, message, msglen);
	qsc_kmac_finalize(&ctx, keccak_rate_256, output, outlen);
}

void qsc_kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	qsc_keccak_state ctx;

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_kmac_initialize(&ctx, keccak_rate_512, key, keylen, custom, custlen);
	qsc_kmac_update(&ctx, keccak_rate_512, message, msglen);
	qsc_kmac_finalize(&ctx, keccak_rate_512, output, outlen);
}

void qsc_kmac_finalize(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t outlen)
{
	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t bitlen;

	qsc_memutils_copy(pad, ctx->buffer, ctx->position);
	bitlen = keccak_right_encode(buf, outlen * 8);
	qsc_memutils_copy(pad + ctx->position, buf, bitlen);

	pad[ctx->position + bitlen] = KECCAK_KMAC_DOMAIN_ID;
	pad[rate - 1] |= 128U;
	keccak_fast_absorb(ctx->state, pad, rate);

	while (outlen >= (size_t)rate)
	{
		keccak_squeezeblocks(ctx->state, pad, 1, rate);
		qsc_memutils_copy(output, pad, rate);
		output += rate;
		outlen -= rate;
	}

	if (outlen > 0)
	{
		keccak_squeezeblocks(ctx->state, pad, 1, rate);
		qsc_memutils_copy(output, pad, outlen);
	}

	qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;
}

void qsc_kmac_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint8_t pad[QSC_KECCAK_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };
	size_t oft;
	size_t i;

	qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
	qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode(pad + oft, sizeof(name) * 8);

	for (i = 0; i < sizeof(name); ++i)
	{
		pad[oft + i] = name[i];
	}

	oft += sizeof(name);
	oft += keccak_left_encode(pad + oft, custlen * 8);

	for (i = 0; i < custlen; ++i)
	{
		if (oft == rate)
		{
			keccak_fast_absorb(ctx->state, pad, rate);
			qsc_keccak_permute(ctx->state);
			oft = 0;
		}

		pad[oft] = custom[i];
		++oft;
	}

	qsc_memutils_clear(pad + oft, rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	qsc_keccak_permute(ctx->state);

	/* stage 2: key */

	qsc_memutils_clear(pad, rate);
	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode(pad + oft, keylen * 8);

	for (i = 0; i < keylen; ++i)
	{
		if (oft == rate)
		{
			keccak_fast_absorb(ctx->state, pad, rate);
			qsc_keccak_permute(ctx->state);
			oft = 0;
		}

		pad[oft] = key[i];
		++oft;
	}

	qsc_memutils_clear(pad + oft, rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	qsc_keccak_permute(ctx->state);
}

void qsc_kmac_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen)
{
	keccak_update(ctx, rate, message, msglen);
}
