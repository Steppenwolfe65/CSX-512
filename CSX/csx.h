/* The GPL version 3 License (GPLv3)
* 
* Copyright (c) 2020 vtdev.com
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
* An implementation of the CSX-512 authenticated stream cipher.
* Written by John G. Underhill
* August 25, 2020
* Contact: develop@vtdev.com */

/**
* \file csx.h
* \brief <b>CSX-512 header definition</b> \n
* ChaCha-based authenticated Stream cipher eXtension.
*
* \author		John G. Underhill
* \version		1.0.0.0b
* \date			May 2, 2020
* \updated		August 25, 2020
* \contact:		develop@vtdev.com
* \copyright	GPL version 3 license (GPLv3)
*
*
* <b>CSX-512 encryption example</b> \n
* \code
* // external message, key, nonce, and custom-info arrays
* const size_t CST_LEN = 20;
* const size_t MSG_LEN = 200;
* uint8_t cust[CST_LEN] = {...};
* uint8_t key[CSX_KEY_SIZE] = {...};
* uint8_t msg[MSG_LEN] = {...};
* uint8_t nonce[CSX_NONCE_SIZE] = {...};
* ...
* uint8_t cpt[MSG_LEN + CSX_MAC_SIZE] = { 0 };
* csx_state state;
* csx_keyparams kp = { key, CSX_KEY_SIZE, nonce, cust, CST_LEN };
*
* // initialize the state
* csx_initialize(&state, &kp, true);
* // encrypt the message
* csx_transform(&state, cpt, msg, MSG_LEN)
* \endcode
*
* <b>CSX-512 decryption example</b> \n
* \code
* // external cipher-text, key and custom-info arrays,
* // and cipher-text containing the encrypted plain-text and the mac-code
* uint8_t cpt[CPT_LEN] = { csx_transform(k,p) }
* uint8_t key[CSX_KEY_SIZE] = {...};
* uint8_t nonce[CSX_NONCE_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* ...
* // subtract the mac-code length from the overall cipher-text length for the message size
* const size_t MSG_LEN = CPT_LEN - CSX_MAC_SIZE;
* uint8_t msg[MSG_LEN] = { 0 };
* csx_keyparams kp = { key, CSX_KEY_SIZE, nonce, cust, CST_LEN };
*
* // initialize the cipher state for decryption
* csx_initialize(&state, &kp, false);
*
* // authenticate and decrypt the cipher-text
* if (csx_transform(&state, msg, cpt, MSG_LEN) == false)
* {
*	// authentication has failed, do something..
* }
* \endcode
*
* \remarks
* <p>An [EXPERIMENTAL] vectorized, 64-bit, 40-round stream cipher [CSX512] implementation based on ChaCha.
* This cipher uses KMAC-512 to authenticate the cipher-text stream in an encrypt-then-mac authentication configuration.
* The CSX (authenticated Cipher Stream, ChaCha eXtended) cipher, is a hybrid of the ChaCha stream cipher, 
* using 64-bit integers, a 1024-bit block and a 512-bit key. \n</p>
*
* <p>The pseudo-random bytes generator used by this cipher is the Keccak cSHAKE extended output function (XOF).
* The cSHAKE XOF is implemented in the 512-bit form of that function, and used to expand the input cipher-key into the cipher and MAC keys.
* CSX-512 uses a 512-bit input key, an a 16 byte nonce, and an optional tweak; the info parameter, up to 48 btes in length.</p>
*
* <p>This is a 'tweakable cipher', the initialization parameters; qsc_csx_keyparams, include an info parameter that can be used as a secondary user input.
* Internally, the info parameter is used to customize the cSHAKE output, using the cSHAKE 'custom' parameter to pre-initialize the SHAKE state.
* The info parameter can be tweaked, with a user defined string 'info' in an qsc_csx_keyparams structure passed to the csx_intitialize(state,keyparams,encrypt).
* This tweak can be used as a 'domain key', or to differentiate cipher-text output from other implementations, or as a secondary secret-key input.</p>
*
* \section Authentication
* <p>CSX is an authenticated encryption with associated data (AEAD) stream cipher.
* The cSHAKE key-expansion function generates a key for the keyed hash-based MAC funtion; KMAC, used to generate the authentication code,
* which is appended to the cipher-text output of an encryption call.
* In decryption mode, before decryption is performed, an internal mac code is calculated, and compared to the code embedded in the cipher-text.
* If authentication fails, the cipher-text is not decrypted, and the qsc_csx_transform(state,out,in,inlen) function returns a boolean false value.
* The csx_set_associated(state,in,inlen) function can be used to add additional data to the MAC generators input, like packet-header data, or a custom code or counter.</p>

* \section Implementation
* The CSX-512, known answer vectors are taken from the CEX++ cryptographic library <a href="https://github.com/Steppenwolfe65/CEX">The CEX++ Cryptographic Library</a>. \n
* See the documentation and the csx_test.h tests for usage examples.</p>
*/

#ifndef QSC_CSX_H
#define QSC_CSX_H

#include "common.h"
#include "sha3.h"

/***********************************
*     CSX CONSTANTS AND SIZES      *
***********************************/

/*!
\def CSX_BLOCK_SIZE
* \brief The internal block size in bytes, required by the encryption and decryption functions.
*/
#define CSX_BLOCK_SIZE 128

/*!
\def CSX_INFO_SIZE
* \brief The maximum byte length of the info string
*/
#define CSX_INFO_SIZE 48

/*!
\def CSX_KEY_SIZE
* \brief The size in bytes of the CSX-512 input cipher-key.
*/
#define CSX_KEY_SIZE 64

/*!
\def CSX512_MAC_LENGTH
* \brief The CSX-512 MAC code array length in bytes.
*/
#define CSX_MAC_SIZE 64

/*!
\def CSX_NONCE_SIZE
* \brief The byte size of the nonce array
*/
#define CSX_NONCE_SIZE 16

/*!
\def CSX_STATE_SIZE
* \brief The uint64 size of the internal state array
*/
#define CSX_STATE_SIZE 14

/*! \struct csx_keyparams
* \brief The key parameters structure containing key, nonce, and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the csx_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
* The nonce is always CSX_BLOCK_SIZE in length.
*/
typedef struct
{
	const uint8_t* key;				/*!< The input cipher key */
	size_t keylen;					/*!< The length in bytes of the cipher key */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
	const uint8_t* info;			/*!< The information tweak */
	size_t infolen;					/*!< The length in bytes of the information tweak */
} csx_keyparams;

/*! \struct csx_state
* \brief The internal state structure containing the round-key array.
*/
typedef struct
{
	uint64_t state[CSX_STATE_SIZE];						/*!< the primary state array */
	uint64_t nonce[CSX_NONCE_SIZE / sizeof(uint64_t)];	/*!< the nonce array */
	keccak_state kstate;								/*!< the kmac state structure */
	uint64_t counter;									/*!< the processed bytes counter */
	uint8_t* aad;										/*!< the additional data array */
	size_t aadlen;										/*!< the additional data array length */
	bool encrypt;										/*!< the transformation mode; true for encryption */
} csx_state;

/* public functions */

/**
* \brief Dispose of the CSX cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays allocated on the heap,
* and must be called before the state goes out of scope.
*
* \param state: [struct] The CSX state structure; contains internal state information
*/
void csx_dispose(csx_state* state);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak.
*
* \param state: [struct] The csx_state structure
* \param keyparams: The secret input cipher-key
* \param encryption: Initialize the cipher for encryption, or false for decryption mode
*/
void csx_initialize(csx_state* state, const csx_keyparams* keyparams, bool encryption);

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The CSX state structure; contains internal state information
* \param data: [const] The associated data array
* \param datalen: The associated data array length
*/
void csx_set_associated(csx_state* state, uint8_t* data, size_t datalen);

/**
* \brief Transform an array of bytes.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the ciphertext.
* In decryption mode, the input cipher-text is authenticated internally and compared to the mac code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The CSX state structure; contains internal state information
* \param keyparams: [struct] The CSX key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
bool csx_transform(csx_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

/* internal test */
void transform_compare();

#endif