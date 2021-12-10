#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "fips202.h"
#include "params.h"

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))
unsigned long rand32bits(void)
{
    unsigned long tmp_r;
    tmp_r = rand();
    tmp_r ^= rand() << 15;
    tmp_r ^= rand() << 30;
    return tmp_r;
}
//secMult from https://www.iacr.org/archive/ches2010/62250403/62250403.pdf
void secMult(uint64_t* c, uint64_t* a, uint64_t* b)
{
    unsigned int i, j, offset_i, offset_j;
    uint64_t r_ij[(KYBER_MASKING_ORDER + 1) * (KYBER_MASKING_ORDER + 1)];
    memset(r_ij, 0, (KYBER_MASKING_ORDER + 1) * (KYBER_MASKING_ORDER + 1) * 8);
    for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
    {
        offset_i = i * (KYBER_MASKING_ORDER + 1);
        for (j = i + 1; j < (KYBER_MASKING_ORDER + 1); j++)
        {
            offset_j = j * (KYBER_MASKING_ORDER + 1);
            r_ij[j + offset_i] = ((uint64_t)(rand32bits()) << 32) + (uint64_t)(rand32bits());
            r_ij[i + offset_j] = (a[i] & b[j]);
            r_ij[i + offset_j] = r_ij[i + offset_j] ^ r_ij[j + offset_i];
            r_ij[i + offset_j] = r_ij[i + offset_j] ^ (a[j] & b[i]);
        }
    }
    for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
    {
        c[i] = a[i] & b[i];
        offset_i = i * (KYBER_MASKING_ORDER + 1);
        for (j = 0; j < (KYBER_MASKING_ORDER + 1); j++)
        {
            if (i != j)
                c[i] = c[i] ^ r_ij[j + offset_i];
        }
    }
    return;
}

void not_mult_xor(uint64_t* r, uint64_t* n, uint64_t* m, uint64_t* x)
{
    unsigned int i;
    //uint64_t tmp_share;
    r[0] = n[0] ^ 0xFFFFFFFFFFFFFFFF;
    for (i = 1; i < (KYBER_MASKING_ORDER + 1); i++)
        r[i] = n[i];
    secMult(r, r, m);
    for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
    {
        r[i] = r[i] ^ x[i];
    }
    return;
}

/*************************************************
* Name:        load64
*
* Description: Load 8 bytes into uint64_t in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns the loaded 64-bit unsigned integer
**************************************************/
static uint64_t load64(const uint8_t x[8]) {
	unsigned int i;
	uint64_t r = 0;

	for (i = 0; i < 8; i++)
		r |= (uint64_t)x[i] << 8 * i;

	return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
*
* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
*              - uint64_t u: input 64-bit unsigned integer
**************************************************/
static void store64(uint8_t x[8], uint64_t u) {
	unsigned int i;

	for (i = 0; i < 8; i++)
		x[i] = u >> 8 * i;
}

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};
void KeccakF1600_StatePermute_masked(uint64_t state_masked[25 * (KYBER_MASKING_ORDER + 1)])
{
    int round, i;

    uint64_t Aba[(KYBER_MASKING_ORDER + 1)], Abe[(KYBER_MASKING_ORDER + 1)], Abi[(KYBER_MASKING_ORDER + 1)], Abo[(KYBER_MASKING_ORDER + 1)], Abu[(KYBER_MASKING_ORDER + 1)];
    uint64_t Aga[(KYBER_MASKING_ORDER + 1)], Age[(KYBER_MASKING_ORDER + 1)], Agi[(KYBER_MASKING_ORDER + 1)], Ago[(KYBER_MASKING_ORDER + 1)], Agu[(KYBER_MASKING_ORDER + 1)];
    uint64_t Aka[(KYBER_MASKING_ORDER + 1)], Ake[(KYBER_MASKING_ORDER + 1)], Aki[(KYBER_MASKING_ORDER + 1)], Ako[(KYBER_MASKING_ORDER + 1)], Aku[(KYBER_MASKING_ORDER + 1)];
    uint64_t Ama[(KYBER_MASKING_ORDER + 1)], Ame[(KYBER_MASKING_ORDER + 1)], Ami[(KYBER_MASKING_ORDER + 1)], Amo[(KYBER_MASKING_ORDER + 1)], Amu[(KYBER_MASKING_ORDER + 1)];
    uint64_t Asa[(KYBER_MASKING_ORDER + 1)], Ase[(KYBER_MASKING_ORDER + 1)], Asi[(KYBER_MASKING_ORDER + 1)], Aso[(KYBER_MASKING_ORDER + 1)], Asu[(KYBER_MASKING_ORDER + 1)];
    uint64_t BCa[(KYBER_MASKING_ORDER + 1)], BCe[(KYBER_MASKING_ORDER + 1)], BCi[(KYBER_MASKING_ORDER + 1)], BCo[(KYBER_MASKING_ORDER + 1)], BCu[(KYBER_MASKING_ORDER + 1)];
    uint64_t Da[(KYBER_MASKING_ORDER + 1)],  De[(KYBER_MASKING_ORDER + 1)],  Di[(KYBER_MASKING_ORDER + 1)],  Do[(KYBER_MASKING_ORDER + 1)],  Du[(KYBER_MASKING_ORDER + 1)];
    uint64_t Eba[(KYBER_MASKING_ORDER + 1)], Ebe[(KYBER_MASKING_ORDER + 1)], Ebi[(KYBER_MASKING_ORDER + 1)], Ebo[(KYBER_MASKING_ORDER + 1)], Ebu[(KYBER_MASKING_ORDER + 1)];
    uint64_t Ega[(KYBER_MASKING_ORDER + 1)], Ege[(KYBER_MASKING_ORDER + 1)], Egi[(KYBER_MASKING_ORDER + 1)], Ego[(KYBER_MASKING_ORDER + 1)], Egu[(KYBER_MASKING_ORDER + 1)];
    uint64_t Eka[(KYBER_MASKING_ORDER + 1)], Eke[(KYBER_MASKING_ORDER + 1)], Eki[(KYBER_MASKING_ORDER + 1)], Eko[(KYBER_MASKING_ORDER + 1)], Eku[(KYBER_MASKING_ORDER + 1)];
    uint64_t Ema[(KYBER_MASKING_ORDER + 1)], Eme[(KYBER_MASKING_ORDER + 1)], Emi[(KYBER_MASKING_ORDER + 1)], Emo[(KYBER_MASKING_ORDER + 1)], Emu[(KYBER_MASKING_ORDER + 1)];
    uint64_t Esa[(KYBER_MASKING_ORDER + 1)], Ese[(KYBER_MASKING_ORDER + 1)], Esi[(KYBER_MASKING_ORDER + 1)], Eso[(KYBER_MASKING_ORDER + 1)], Esu[(KYBER_MASKING_ORDER + 1)];

    //copyFromState(A, state)
    for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
    {
        Aba[i] = state_masked[ 0+(i*25)];
        Abe[i] = state_masked[ 1+(i*25)];
        Abi[i] = state_masked[ 2+(i*25)];
        Abo[i] = state_masked[ 3+(i*25)];
        Abu[i] = state_masked[ 4+(i*25)];
        Aga[i] = state_masked[ 5+(i*25)];
        Age[i] = state_masked[ 6+(i*25)];
        Agi[i] = state_masked[ 7+(i*25)];
        Ago[i] = state_masked[ 8+(i*25)];
        Agu[i] = state_masked[ 9+(i*25)];
        Aka[i] = state_masked[10+(i*25)];
        Ake[i] = state_masked[11+(i*25)];
        Aki[i] = state_masked[12+(i*25)];
        Ako[i] = state_masked[13+(i*25)];
        Aku[i] = state_masked[14+(i*25)];
        Ama[i] = state_masked[15+(i*25)];
        Ame[i] = state_masked[16+(i*25)];
        Ami[i] = state_masked[17+(i*25)];
        Amo[i] = state_masked[18+(i*25)];
        Amu[i] = state_masked[19+(i*25)];
        Asa[i] = state_masked[20+(i*25)];
        Ase[i] = state_masked[21+(i*25)];
        Asi[i] = state_masked[22+(i*25)];
        Aso[i] = state_masked[23+(i*25)];
        Asu[i] = state_masked[24+(i*25)];
    }
    for (round = 0; round < NROUNDS; round += 2)
    {
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            //    prepareTheta
            BCa[i] = Aba[i] ^ Aga[i] ^ Aka[i] ^ Ama[i] ^ Asa[i];
            BCe[i] = Abe[i] ^ Age[i] ^ Ake[i] ^ Ame[i] ^ Ase[i];
            BCi[i] = Abi[i] ^ Agi[i] ^ Aki[i] ^ Ami[i] ^ Asi[i];
            BCo[i] = Abo[i] ^ Ago[i] ^ Ako[i] ^ Amo[i] ^ Aso[i];
            BCu[i] = Abu[i] ^ Agu[i] ^ Aku[i] ^ Amu[i] ^ Asu[i];

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da[i] = BCu[i] ^ ROL(BCe[i], 1);
            De[i] = BCa[i] ^ ROL(BCi[i], 1);
            Di[i] = BCe[i] ^ ROL(BCo[i], 1);
            Do[i] = BCi[i] ^ ROL(BCu[i], 1);
            Du[i] = BCo[i] ^ ROL(BCa[i], 1);

            Aba[i] ^= Da[i];
            BCa[i] = Aba[i];
            Age[i] ^= De[i];
            BCe[i] = ROL(Age[i], 44);
            Aki[i] ^= Di[i];
            BCi[i] = ROL(Aki[i], 43);
            Amo[i] ^= Do[i];
            BCo[i] = ROL(Amo[i], 21);
            Asu[i] ^= Du[i];
            BCu[i] = ROL(Asu[i], 14);
        }
        not_mult_xor(Eba, BCe, BCi, BCa);
        Eba[0] ^= (uint64_t)KeccakF_RoundConstants[round];
        not_mult_xor(Ebe, BCi, BCo, BCe);
        not_mult_xor(Ebi, BCo, BCu, BCi);
        not_mult_xor(Ebo, BCu, BCa, BCo);
        not_mult_xor(Ebu, BCa, BCe, BCu);
        //Eba[i] = BCa ^ ((~BCe) & BCi);
        //Eba[i] ^= (uint64_t)KeccakF_RoundConstants[round];
        //Ebe[i] = BCe ^ ((~BCi) & BCo);
        //Ebi[i] = BCi ^ ((~BCo) & BCu);
        //Ebo[i] = BCo ^ ((~BCu) & BCa);
        //Ebu[i] = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Abo[i] ^= Do[i];
            BCa[i] = ROL(Abo[i], 28);
            Agu[i] ^= Du[i];
            BCe[i] = ROL(Agu[i], 20);
            Aka[i] ^= Da[i];
            BCi[i] = ROL(Aka[i], 3);
            Ame[i] ^= De[i];
            BCo[i] = ROL(Ame[i], 45);
            Asi[i] ^= Di[i];
            BCu[i] = ROL(Asi[i], 61);
        }
        not_mult_xor(Ega, BCe, BCi, BCa);
        not_mult_xor(Ege, BCi, BCo, BCe);
        not_mult_xor(Egi, BCo, BCu, BCi);
        not_mult_xor(Ego, BCu, BCa, BCo);
        not_mult_xor(Egu, BCa, BCe, BCu);
        //Ega = BCa ^ ((~BCe) & BCi);
        //Ege = BCe ^ ((~BCi) & BCo);
        //Egi = BCi ^ ((~BCo) & BCu);
        //Ego = BCo ^ ((~BCu) & BCa);
        //Egu = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Abe[i] ^= De[i];
            BCa[i] = ROL(Abe[i], 1);
            Agi[i] ^= Di[i];
            BCe[i] = ROL(Agi[i], 6);
            Ako[i] ^= Do[i];
            BCi[i] = ROL(Ako[i], 25);
            Amu[i] ^= Du[i];
            BCo[i] = ROL(Amu[i], 8);
            Asa[i] ^= Da[i];
            BCu[i] = ROL(Asa[i], 18);
        }
        not_mult_xor(Eka, BCe, BCi, BCa);
        not_mult_xor(Eke, BCi, BCo, BCe);
        not_mult_xor(Eki, BCo, BCu, BCi);
        not_mult_xor(Eko, BCu, BCa, BCo);
        not_mult_xor(Eku, BCa, BCe, BCu);
        //Eka = BCa ^ ((~BCe) & BCi);
        //Eke = BCe ^ ((~BCi) & BCo);
        //Eki = BCi ^ ((~BCo) & BCu);
        //Eko = BCo ^ ((~BCu) & BCa);
        //Eku = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Abu[i] ^= Du[i];
            BCa[i] = ROL(Abu[i], 27);
            Aga[i] ^= Da[i];
            BCe[i] = ROL(Aga[i], 36);
            Ake[i] ^= De[i];
            BCi[i] = ROL(Ake[i], 10);
            Ami[i] ^= Di[i];
            BCo[i] = ROL(Ami[i], 15);
            Aso[i] ^= Do[i];
            BCu[i] = ROL(Aso[i], 56);
        }
        not_mult_xor(Ema, BCe, BCi, BCa);
        not_mult_xor(Eme, BCi, BCo, BCe);
        not_mult_xor(Emi, BCo, BCu, BCi);
        not_mult_xor(Emo, BCu, BCa, BCo);
        not_mult_xor(Emu, BCa, BCe, BCu);
        //Ema = BCa ^ ((~BCe) & BCi);
        //Eme = BCe ^ ((~BCi) & BCo);
        //Emi = BCi ^ ((~BCo) & BCu);
        //Emo = BCo ^ ((~BCu) & BCa);
        //Emu = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Abi[i] ^= Di[i];
            BCa[i] = ROL(Abi[i], 62);
            Ago[i] ^= Do[i];
            BCe[i] = ROL(Ago[i], 55);
            Aku[i] ^= Du[i];
            BCi[i] = ROL(Aku[i], 39);
            Ama[i] ^= Da[i];
            BCo[i] = ROL(Ama[i], 41);
            Ase[i] ^= De[i];
            BCu[i] = ROL(Ase[i], 2);
        }
        not_mult_xor(Esa, BCe, BCi, BCa);
        not_mult_xor(Ese, BCi, BCo, BCe);
        not_mult_xor(Esi, BCo, BCu, BCi);
        not_mult_xor(Eso, BCu, BCa, BCo);
        not_mult_xor(Esu, BCa, BCe, BCu);
        //Esa = BCa ^ ((~BCe) & BCi);
        //Ese = BCe ^ ((~BCi) & BCo);
        //Esi = BCi ^ ((~BCo) & BCu);
        //Eso = BCo ^ ((~BCu) & BCa);
        //Esu = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            //    prepareTheta
            BCa[i] = Eba[i] ^ Ega[i] ^ Eka[i] ^ Ema[i] ^ Esa[i];
            BCe[i] = Ebe[i] ^ Ege[i] ^ Eke[i] ^ Eme[i] ^ Ese[i];
            BCi[i] = Ebi[i] ^ Egi[i] ^ Eki[i] ^ Emi[i] ^ Esi[i];
            BCo[i] = Ebo[i] ^ Ego[i] ^ Eko[i] ^ Emo[i] ^ Eso[i];
            BCu[i] = Ebu[i] ^ Egu[i] ^ Eku[i] ^ Emu[i] ^ Esu[i];

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da[i] = BCu[i] ^ ROL(BCe[i], 1);
            De[i] = BCa[i] ^ ROL(BCi[i], 1);
            Di[i] = BCe[i] ^ ROL(BCo[i], 1);
            Do[i] = BCi[i] ^ ROL(BCu[i], 1);
            Du[i] = BCo[i] ^ ROL(BCa[i], 1);

            Eba[i] ^= Da[i];
            BCa[i] = Eba[i];
            Ege[i] ^= De[i];
            BCe[i] = ROL(Ege[i], 44);
            Eki[i] ^= Di[i];
            BCi[i] = ROL(Eki[i], 43);
            Emo[i] ^= Do[i];
            BCo[i] = ROL(Emo[i], 21);
            Esu[i] ^= Du[i];
            BCu[i] = ROL(Esu[i], 14);
        }
        not_mult_xor(Aba, BCe, BCi, BCa);
        Aba[0] ^= (uint64_t)KeccakF_RoundConstants[round + 1];
        not_mult_xor(Abe, BCi, BCo, BCe);
        not_mult_xor(Abi, BCo, BCu, BCi);
        not_mult_xor(Abo, BCu, BCa, BCo);
        not_mult_xor(Abu, BCa, BCe, BCu);
        //Aba = BCa ^ ((~BCe) & BCi);
        //Aba ^= (uint64_t)KeccakF_RoundConstants[round + 1];
        //Abe = BCe ^ ((~BCi) & BCo);
        //Abi = BCi ^ ((~BCo) & BCu);
        //Abo = BCo ^ ((~BCu) & BCa);
        //Abu = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Ebo[i] ^= Do[i];
            BCa[i] = ROL(Ebo[i], 28);
            Egu[i] ^= Du[i];
            BCe[i] = ROL(Egu[i], 20);
            Eka[i] ^= Da[i];
            BCi[i] = ROL(Eka[i], 3);
            Eme[i] ^= De[i];
            BCo[i] = ROL(Eme[i], 45);
            Esi[i] ^= Di[i];
            BCu[i] = ROL(Esi[i], 61);
        }
        not_mult_xor(Aga, BCe, BCi, BCa);
        not_mult_xor(Age, BCi, BCo, BCe);
        not_mult_xor(Agi, BCo, BCu, BCi);
        not_mult_xor(Ago, BCu, BCa, BCo);
        not_mult_xor(Agu, BCa, BCe, BCu);
        //Aga = BCa ^ ((~BCe) & BCi);
        //Age = BCe ^ ((~BCi) & BCo);
        //Agi = BCi ^ ((~BCo) & BCu);
        //Ago = BCo ^ ((~BCu) & BCa);
        //Agu = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Ebe[i] ^= De[i];
            BCa[i] = ROL(Ebe[i], 1);
            Egi[i] ^= Di[i];
            BCe[i] = ROL(Egi[i], 6);
            Eko[i] ^= Do[i];
            BCi[i] = ROL(Eko[i], 25);
            Emu[i] ^= Du[i];
            BCo[i] = ROL(Emu[i], 8);
            Esa[i] ^= Da[i];
            BCu[i] = ROL(Esa[i], 18);
        }
        not_mult_xor(Aka, BCe, BCi, BCa);
        not_mult_xor(Ake, BCi, BCo, BCe);
        not_mult_xor(Aki, BCo, BCu, BCi);
        not_mult_xor(Ako, BCu, BCa, BCo);
        not_mult_xor(Aku, BCa, BCe, BCu);
        //Aka = BCa ^ ((~BCe) & BCi);
        //Ake = BCe ^ ((~BCi) & BCo);
        //Aki = BCi ^ ((~BCo) & BCu);
        //Ako = BCo ^ ((~BCu) & BCa);
        //Aku = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Ebu[i] ^= Du[i];
            BCa[i] = ROL(Ebu[i], 27);
            Ega[i] ^= Da[i];
            BCe[i] = ROL(Ega[i], 36);
            Eke[i] ^= De[i];
            BCi[i] = ROL(Eke[i], 10);
            Emi[i] ^= Di[i];
            BCo[i] = ROL(Emi[i], 15);
            Eso[i] ^= Do[i];
            BCu[i] = ROL(Eso[i], 56);
        }
        not_mult_xor(Ama, BCe, BCi, BCa);
        not_mult_xor(Ame, BCi, BCo, BCe);
        not_mult_xor(Ami, BCo, BCu, BCi);
        not_mult_xor(Amo, BCu, BCa, BCo);
        not_mult_xor(Amu, BCa, BCe, BCu);
        //Ama = BCa ^ ((~BCe) & BCi);
        //Ame = BCe ^ ((~BCi) & BCo);
        //Ami = BCi ^ ((~BCo) & BCu);
        //Amo = BCo ^ ((~BCu) & BCa);
        //Amu = BCu ^ ((~BCa) & BCe);
        for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
        {
            Ebi[i] ^= Di[i];
            BCa[i] = ROL(Ebi[i], 62);
            Ego[i] ^= Do[i];
            BCe[i] = ROL(Ego[i], 55);
            Eku[i] ^= Du[i];
            BCi[i] = ROL(Eku[i], 39);
            Ema[i] ^= Da[i];
            BCo[i] = ROL(Ema[i], 41);
            Ese[i] ^= De[i];
            BCu[i] = ROL(Ese[i], 2);
        }
        not_mult_xor(Asa, BCe, BCi, BCa);
        not_mult_xor(Ase, BCi, BCo, BCe);
        not_mult_xor(Asi, BCo, BCu, BCi);
        not_mult_xor(Aso, BCu, BCa, BCo);
        not_mult_xor(Asu, BCa, BCe, BCu);
        //Asa = BCa ^ ((~BCe) & BCi);
        //Ase = BCe ^ ((~BCi) & BCo);
        //Asi = BCi ^ ((~BCo) & BCu);
        //Aso = BCo ^ ((~BCu) & BCa);
        //Asu = BCu ^ ((~BCa) & BCe);
    }

    for (i = 0; i < (KYBER_MASKING_ORDER + 1); i++)
    {
        //copyToState(state, A)
        state_masked[ 0+(i*25)] = Aba[i];
        state_masked[ 1+(i*25)] = Abe[i];
        state_masked[ 2+(i*25)] = Abi[i];
        state_masked[ 3+(i*25)] = Abo[i];
        state_masked[ 4+(i*25)] = Abu[i];
        state_masked[ 5+(i*25)] = Aga[i];
        state_masked[ 6+(i*25)] = Age[i];
        state_masked[ 7+(i*25)] = Agi[i];
        state_masked[ 8+(i*25)] = Ago[i];
        state_masked[ 9+(i*25)] = Agu[i];
        state_masked[10+(i*25)] = Aka[i];
        state_masked[11+(i*25)] = Ake[i];
        state_masked[12+(i*25)] = Aki[i];
        state_masked[13+(i*25)] = Ako[i];
        state_masked[14+(i*25)] = Aku[i];
        state_masked[15+(i*25)] = Ama[i];
        state_masked[16+(i*25)] = Ame[i];
        state_masked[17+(i*25)] = Ami[i];
        state_masked[18+(i*25)] = Amo[i];
        state_masked[19+(i*25)] = Amu[i];
        state_masked[20+(i*25)] = Asa[i];
        state_masked[21+(i*25)] = Ase[i];
        state_masked[22+(i*25)] = Asi[i];
        state_masked[23+(i*25)] = Aso[i];
        state_masked[24+(i*25)] = Asu[i];
    }
	return;
}

/*************************************************
* Name:        keccak_absorb_masked
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - const uint8_t *m: pointer to input to be absorbed into s
*              - size_t mlen: length of input in bytes
*              - uint8_t p: domain-separation byte for different
*                           Keccak-derived functions
**************************************************/
 void keccak_absorb_masked(uint64_t s_masked[25 * (KYBER_MASKING_ORDER + 1)],
                           unsigned int r,
                           const uint8_t* m_masked,
                           size_t mlen,
                           uint8_t p)
{
    size_t i, tmp_mlen;
    unsigned int l;
    uint8_t t[200*(KYBER_MASKING_ORDER+1)] = { 0 };
    tmp_mlen = mlen;
    /* Zero state */
    for (l = 0; l < (KYBER_MASKING_ORDER + 1); l++)
    {
        for (i = 0; i < 25; i++)
            s_masked[i+(25*l)] = 0;
    }
    
    while (mlen >= r) {
        for (l = 0; l < (KYBER_MASKING_ORDER + 1); l++)
        {
            for (i = 0; i < r / 8; i++)
                s_masked[i + (l * 25)] ^= load64(m_masked + (8 * i) + (l*tmp_mlen));
        }
        KeccakF1600_StatePermute_masked(s_masked);
        mlen -= r;
        m_masked += r;
    }
    for (l = 0; l < (KYBER_MASKING_ORDER + 1); l++)
    {
        for (i = 0; i < mlen; i++)
            t[i + (200 * l)] = m_masked[i + (l * tmp_mlen)];
        t[i] = p; //Only in the first share
        t[r - 1] |= 128; //Only in the first share
        for (i = 0; i < r / 8; i++)
            s_masked[i + (25 * l)] ^= load64(t + (8 * i) + (200 * l));
    }
}
/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *h: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to h)
*              - uint64_t *s: pointer to input/output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks_masked(uint8_t* out_masked,
                                        size_t nblocks,
                                        uint64_t s_masked[25*(KYBER_MASKING_ORDER+1)],
                                        unsigned int r,
                                        size_t outlen)
{
    unsigned int i,l,offset;
    if (outlen == 0)
        offset = r * nblocks;
    else
        offset = outlen;
    while (nblocks > 0)
    {
        KeccakF1600_StatePermute_masked(s_masked);
        for (l = 0; l < (KYBER_MASKING_ORDER + 1); l++)
        {
            for (i = 0; i < r / 8; i++)
                store64(out_masked + (8 * i) + (l* offset), s_masked[i+(l*25)]);
        }
        out_masked += r;
        --nblocks;
    }
    return;
}
/*************************************************
* Name:        shake128_absorb_masked
*
* Description: Absorb step of the SHAKE128 XOF.
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output
*                                     Keccak state
*              - const uint8_t *in:   pointer to input to be absorbed into s
*              - size_t inlen:        length of input in bytes
**************************************************/
void shake128_absorb_masked(keccak_state_masked* state_masked, const uint8_t* in_masked, size_t inlen)
{
    keccak_absorb_masked(state_masked->s_masked, SHAKE128_RATE, in_masked, inlen, 0x1F);
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
*              SHAKE128_RATE bytes each. Modifies the state. Can be called
*              multiple times to keep squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t nblocks:  number of blocks to be squeezed
*                                 (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeezeblocks_masked(uint8_t* out_masked, size_t nblocks, keccak_state_masked* state_masked, size_t outlen)
{
    keccak_squeezeblocks_masked(out_masked, nblocks, state_masked->s_masked, SHAKE128_RATE, outlen);
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of the SHAKE256 XOF.
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - keccak_state *s:   pointer to (uninitialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake256_absorb_masked(keccak_state_masked* state_masked, const uint8_t* in_masked, size_t inlen)
{
    keccak_absorb_masked(state_masked->s_masked, SHAKE256_RATE, in_masked, inlen, 0x1F);
}

/*************************************************
* Name:        shake256_squeezeblocks
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
*              SHAKE256_RATE bytes each. Modifies the state. Can be called
*              multiple times to keep squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *out:    pointer to output blocks
*              - size_t nblocks:  number of blocks to be squeezed
*                                 (written to output)
*              - keccak_State *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeezeblocks_masked(uint8_t* out_masked, size_t nblocks, keccak_state_masked* state_masked, size_t outlen)
{
    keccak_squeezeblocks_masked(out_masked, nblocks, state_masked->s_masked, SHAKE256_RATE, outlen);
}

/*************************************************
* Name:        shake128
*
* Description: SHAKE128 XOF with non-incremental API
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake128_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen)
{
    unsigned int i,l;
    size_t tmp_outlen;
    size_t nblocks = outlen / SHAKE128_RATE;
    uint8_t t_masked[SHAKE128_RATE*(KYBER_MASKING_ORDER+1)];
    keccak_state_masked state_masked;

    tmp_outlen = outlen;
    shake128_absorb_masked(&state_masked, in_masked, inlen);
    shake128_squeezeblocks_masked(out_masked, nblocks, &state_masked, tmp_outlen);

    out_masked += nblocks * SHAKE128_RATE;
    outlen -= nblocks * SHAKE128_RATE;

    if (outlen) {
        shake128_squeezeblocks_masked(t_masked, 1, &state_masked, 0);
        for (l = 0; l < (KYBER_MASKING_ORDER + 1); l++)
        {
            for (i = 0; i < outlen; i++)
                out_masked[i+(l* tmp_outlen)] = t_masked[i+(l* SHAKE128_RATE)];
        }
    }
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - uint8_t *out:      pointer to output
*              - size_t outlen:     requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void shake256_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen)
{
    unsigned int i,l;
    size_t tmp_outlen;
    size_t nblocks = outlen / SHAKE256_RATE;
    uint8_t t_masked[SHAKE256_RATE*(KYBER_MASKING_ORDER+1)];
    keccak_state_masked state_masked;

    tmp_outlen = outlen;
    shake256_absorb_masked(&state_masked, in_masked, inlen);
    shake256_squeezeblocks_masked(out_masked, nblocks, &state_masked, tmp_outlen);

    out_masked += nblocks * SHAKE256_RATE;
    outlen -= nblocks * SHAKE256_RATE;

    if (outlen) {
        shake256_squeezeblocks_masked(t_masked, 1, &state_masked, 0);
        for (l = 0; l < (KYBER_MASKING_ORDER + 1); l++)
        {
            for (i = 0; i < outlen; i++)
                out_masked[i + (l * tmp_outlen)] = t_masked[i + (l * SHAKE256_RATE)];
        }
    }
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (32 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sha3_256_masked(uint8_t h_masked[32*(KYBER_MASKING_ORDER+1)], const uint8_t* in_masked, size_t inlen)
{
    unsigned int i,l;
    uint64_t s_masked[25*(KYBER_MASKING_ORDER+1)];
    uint8_t t_masked[SHA3_256_RATE*(KYBER_MASKING_ORDER+1)];

    keccak_absorb_masked(s_masked, SHA3_256_RATE, in_masked, inlen, 0x06);
    keccak_squeezeblocks_masked(t_masked, 1, s_masked, SHA3_256_RATE, 0);

    for (l = 0; l < (KYBER_MASKING_ORDER+1); l++)
    {
        for (i = 0; i < 32; i++)
            h_masked[i+(l*32)] = t_masked[i+(l*SHA3_256_RATE)];
    }
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - uint8_t *h:        pointer to output (64 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen:      length of input in bytes
**************************************************/
void sha3_512_masked(uint8_t h_masked[64 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen)
{
    unsigned int i,l;
    uint64_t s_masked[25 * (KYBER_MASKING_ORDER + 1)];
    uint8_t t_masked[SHA3_512_RATE*(KYBER_MASKING_ORDER+1)];

    keccak_absorb_masked(s_masked, SHA3_512_RATE, in_masked, inlen, 0x06);
    keccak_squeezeblocks_masked(t_masked, 1, s_masked, SHA3_512_RATE, 0);

    for (l = 0; l < (KYBER_MASKING_ORDER+1); l++)
    {
        for (i = 0; i < 64; i++)
            h_masked[i+(l*64)] = t_masked[i+(l* SHA3_512_RATE)];
    }
}