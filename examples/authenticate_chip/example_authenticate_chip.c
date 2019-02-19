/**
* MIT License
*
* Copyright (c) 2018 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*
* \file example_optiga_crypt_ecdsa_sign.c
*
* \brief   This file provides the example for ECDSA Sign operation using #optiga_crypt_ecdsa_sign.
*
*
* \ingroup
* @{
*/

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/common/AuthLibSettings.h"
#include "pal_crypt.h"
#include <openssl/x509.h>
#include <openssl/pem.h>

///size of public key for NIST-P256
#define LENGTH_PUB_KEY_NISTP256     0x41

///Length of R and S vector
#define LENGTH_RS_VECTOR            0x40

///Length of maximum additional bytes to encode sign in DER
#define MAXLENGTH_SIGN_ENCODE       0x06

///Length of Signature
#define LENGTH_SIGNATURE            (LENGTH_RS_VECTOR + MAXLENGTH_SIGN_ENCODE)

// Length of the requested challenge
#define LENGTH_CHALLENGE			32

// Length of SH256
#define LENGTH_SHA256			32

///size of end entity certificate of OPTIGA™ Trust X
#define LENGTH_OPTIGA_CERT          512

#ifdef MODULE_ENABLE_ONE_WAY_AUTH

// OPTIGA™ Trust X Root CA. Hexadeciaml representation of the "Infineon OPTIGA(TM) Trust X CA 101" certificate
uint8_t optiga_ca_certificate[] = {
		0x30, 0x82, 0x02, 0x78, 0x30, 0x82, 0x01, 0xfe, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x6a,
		0xdb, 0xdd, 0xd6, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30,
		0x77, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x21,
		0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f,
		0x6e, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x20, 0x41,
		0x47, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x12, 0x4f, 0x50, 0x54, 0x49,
		0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x31, 0x28,
		0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1f, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f,
		0x6e, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x20, 0x45, 0x43, 0x43,
		0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x38,
		0x32, 0x39, 0x31, 0x36, 0x32, 0x37, 0x30, 0x38, 0x5a, 0x17, 0x0d, 0x34, 0x32, 0x30, 0x38, 0x32,
		0x39, 0x31, 0x36, 0x32, 0x37, 0x30, 0x38, 0x5a, 0x30, 0x72, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
		0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
		0x0c, 0x18, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f, 0x6e, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e,
		0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x20, 0x41, 0x47, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
		0x55, 0x04, 0x0b, 0x0c, 0x0a, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x31,
		0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x22, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65,
		0x6f, 0x6e, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x20, 0x54, 0x72,
		0x75, 0x73, 0x74, 0x20, 0x58, 0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13,
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x60, 0xd7, 0x9d, 0x39, 0x60, 0xfb, 0x10, 0xd4, 0x28,
		0x89, 0x09, 0x56, 0x4f, 0xfd, 0xa8, 0x47, 0xe2, 0x22, 0xfd, 0x8d, 0x3a, 0x24, 0x07, 0x7b, 0x38,
		0x0d, 0xc3, 0x70, 0x4e, 0x37, 0x42, 0x08, 0x1b, 0x33, 0xc6, 0xec, 0x47, 0xd0, 0xa8, 0xfb, 0xcf,
		0xad, 0x3f, 0xdc, 0x7c, 0x6e, 0xcd, 0x94, 0x7a, 0x4c, 0x1e, 0x90, 0x63, 0xd0, 0x7f, 0xe4, 0x20,
		0xa7, 0xab, 0x14, 0xd5, 0x92, 0xb6, 0xc0, 0xa3, 0x7d, 0x30, 0x7b, 0x30, 0x1d, 0x06, 0x03, 0x55,
		0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xca, 0x05, 0x33, 0xd7, 0x4f, 0xc4, 0x7f, 0x09, 0x49, 0xfb,
		0xdb, 0x12, 0x25, 0xdf, 0xd7, 0x97, 0x9d, 0x41, 0x1e, 0x15, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
		0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x00, 0x04, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d,
		0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x15,
		0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0e, 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x82, 0x14,
		0x00, 0x44, 0x01, 0x14, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
		0x80, 0x14, 0xb4, 0x18, 0x85, 0xc8, 0x4a, 0x4a, 0xc5, 0x12, 0x7a, 0xf2, 0x40, 0x39, 0xde, 0xc4,
		0xf5, 0x8b, 0x1e, 0x7e, 0x4a, 0xd1, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
		0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xd2, 0x21, 0x49, 0xc3, 0x46, 0x70,
		0x4b, 0x16, 0x85, 0x9e, 0xf2, 0x92, 0x6d, 0x0c, 0xd2, 0xb8, 0x74, 0x4f, 0xdd, 0x12, 0x61, 0x78,
		0x45, 0x9b, 0x54, 0x31, 0xd2, 0x9d, 0x50, 0x4a, 0xdd, 0x5c, 0xfe, 0xf7, 0x54, 0x12, 0xb8, 0x03,
		0xc2, 0x11, 0x21, 0x95, 0x53, 0xfc, 0x30, 0x39, 0x00, 0xd6, 0x02, 0x30, 0x13, 0x62, 0x98, 0x1f,
		0xe7, 0x64, 0x4c, 0x89, 0xef, 0xf0, 0xe7, 0x83, 0xeb, 0x71, 0x5c, 0xa1, 0xae, 0x47, 0xf7, 0xe7,
		0xfb, 0x7e, 0x70, 0xa8, 0xdf, 0x28, 0x04, 0x14, 0x42, 0x47, 0x66, 0x70, 0x62, 0x22, 0x1d, 0xbf,
		0xf3, 0xe6, 0xb3, 0x5e, 0x23, 0xcb, 0x29, 0x32, 0xde, 0xea, 0xb5, 0x8e
};

/**
*
* Retrieves an End Device Certificate stored in OPTIGA™ Trust X
*
* \param[in]        chip_cert_oid          Certificate OID
* \param[in]        chip_pubkey	           Pointer to public key buffer
* \param[in,out]    chip_pubkey_size	   Pointer to public key buffer size
*
* \retval    #OPTIGA_LIB_SUCCESS
* \retval    #OPTIGA_LIB_ERROR
*
*/

static optiga_lib_status_t __get_chip_cert(uint16_t ,
		                                   uint8_t* , uint16_t* );

uint32_t save_chip_cert(void)
{
	optiga_lib_status_t ret;
	uint8_t chip_cert[LENGTH_OPTIGA_CERT];
	uint16_t chip_cert_size = LENGTH_OPTIGA_CERT;
	uint16_t chip_cert_oid = eDEVICE_PUBKEY_CERT_IFX;
	printf("Reading chip certificate\n" );
  ret = __get_chip_cert(chip_cert_oid, chip_cert, &chip_cert_size);
	printf("Got it\n" );
	// for (int i=0; i<chip_cert_size;i++) {
	// 	printf("%x ", chip_cert[i]);
  // }
	// printf("\n" );

	const uint8_t * cert_buf;
	cert_buf = &chip_cert[0];
	X509 *cert = d2i_X509(NULL, &cert_buf, chip_cert_size);



	if (cert != NULL) {
		printf("Generated X509\n");
		FILE * f;
		f = fopen("cert.pem", "wb");
		PEM_write_X509(
    f,   /* write the certificate to the file we've opened */
    cert /* our certificate */
);
	}

	return 0;
}

static optiga_lib_status_t __get_chip_cert(uint16_t cert_oid,
		                                   uint8_t* p_cert, uint16_t* p_cert_size)
{
	printf("__get_chip_cert\n" );

	int32_t status  = (int32_t)OPTIGA_LIB_ERROR;
	// We might need to modify a certificate buffer pointer
	uint8_t tmp_cert[LENGTH_OPTIGA_CERT];
	uint8_t* p_tmp_cert_pointer = tmp_cert;

	do
	{
		printf("sanity check\n");
		// Sanity check
		if ((NULL == p_cert) || (NULL == p_cert_size) ||
			(0 == cert_oid) || (0 == *p_cert_size))
		{
			printf("Passed NULL to __get_chip_cert\n" );
			break;
		}

		//Get end entity device certificate
		printf("optiga_util_read_data\n");
		status = optiga_util_read_data(cert_oid, 0, p_tmp_cert_pointer, p_cert_size);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			printf("Failed to optiga_util_read_data\n");
			break;
		}

		printf("Retrieved certificate, parsing data\n");

		// Refer to the Solution Reference Manual (SRM) v1.35 Table 30. Certificate Types
		switch (p_tmp_cert_pointer[0])
		{
		/* One-Way Authentication Identity. Certificate DER coded The first byte
		*  of the DER encoded certificate is 0x30 and is used as Tag to differentiate
		*  from other Public Key Certificate formats defined below.
		*/
		case 0x30:
			/* The certificate can be directly used */
			status = OPTIGA_LIB_SUCCESS;
			break;
		/* TLS Identity. Tag = 0xC0; Length = Value length (2 Bytes); Value = Certificate Chain
		 * Format of a "Certificate Structure Message" used in TLS Handshake
		 */
		case 0xC0:
			/* There might be a certificate chain encoded.
			 * For this example we will consider only one certificate in the chain
			 */
			p_tmp_cert_pointer = p_tmp_cert_pointer + 9;
			*p_cert_size = *p_cert_size - 9;
			memcpy(p_cert, p_tmp_cert_pointer, *p_cert_size);
			status = OPTIGA_LIB_SUCCESS;
			break;
		/* USB Type-C identity
		 * Tag = 0xC2; Length = Value length (2 Bytes); Value = USB Type-C Certificate Chain [USB Auth].
		 * Format as defined in Section 3.2 of the USB Type-C Authentication Specification (SRM)
		 */
		case 0xC2:
		// Not supported for this example
		// Certificate type isn't supported or a wrong tag
		default:
			break;
		}

	}while(FALSE);

	return status;
}

/**
*
* Authenticate end device entity.<br>
*
* \param[in]  PwChallengeLen		Length of the challenge to be generated
* \param[in]  PpsOPTIGAPublicKey	Pointer blob to store end entity device public key
* \param[in]  PwOPTIGAPrivKey		Private key to be used for set auth scheme
*
* \retval    #INT_LIB_OK
* \retval    #INT_LIB_ERROR
* \retval    #INT_LIB_MALLOC_FAILURE
*
*/
// static optiga_lib_status_t __authenticate_chip(uint8_t* p_pubkey, uint16_t pubkey_size, uint16_t privkey_oid)
// {
//     int32_t status  = OPTIGA_LIB_ERROR;
//     uint8_t random[LENGTH_CHALLENGE];
//     uint8_t signature[LENGTH_SIGNATURE];
//     uint16_t signature_size = LENGTH_SIGNATURE;
//     uint8_t digest[LENGTH_SHA256];
//
//     do
//     {
//         //Get PwChallengeLen byte random stream
//         status = pal_crypt_random(LENGTH_CHALLENGE, random);
//         if(OPTIGA_LIB_SUCCESS != status)
//         {
//             break;
//         }
//
//         status = pal_crypt_generate_sha256(random, LENGTH_CHALLENGE, digest);
//         if(OPTIGA_LIB_SUCCESS != status)
//         {
//         	status = (int32_t)CRYPTO_LIB_VERIFY_SIGN_FAIL;
//             break;
//         }
//
// 		//Sign random with OPTIGA™ Trust X
//         status = optiga_crypt_ecdsa_sign(digest, LENGTH_SHA256,
// 									     privkey_oid,
// 										 signature, &signature_size);
//         if (OPTIGA_LIB_SUCCESS != status)
//         {
// 			// Signature generation failed
//             break;
//         }
//
// 		//Verify the signature on the random number by Security Chip
// 		status = pal_crypt_verify_signature(p_pubkey, pubkey_size,
// 				                            signature, signature_size,
// 											digest, LENGTH_SHA256);
// 		if(OPTIGA_LIB_SUCCESS != status)
// 		{
// 			break;
// 		}
// 	} while (FALSE);
//
//     return status;
// }
//
// /**
//  * The below example demonstrates the authetnication of the security chip
//  * using third party crypto library.
//  *
//  * Example for #example_authenticate_chip
//  *
//  */
// optiga_lib_status_t example_authenticate_chip(void)
// {
//     optiga_lib_status_t status;
// 	uint8_t chip_cert[LENGTH_OPTIGA_CERT];
// 	uint16_t chip_cert_size = LENGTH_OPTIGA_CERT;
// 	uint8_t chip_pubkey[LENGTH_PUB_KEY_NISTP256];
// 	uint16_t chip_pubkey_size = LENGTH_PUB_KEY_NISTP256;
// 	uint16_t chip_cert_oid = eDEVICE_PUBKEY_CERT_IFX;
// 	uint16_t chip_privkey_oid = eFIRST_DEVICE_PRIKEY_1;
//
//     do
//     {
//     	// Initialise pal crypto module
//     	status = pal_crypt_init();
// 		if(OPTIGA_LIB_SUCCESS != status)
// 		{
// 			break;
// 		}
//
// 		// Retrieve a Certificate of the security chip
//     	status = __get_chip_cert(chip_cert_oid, chip_cert, &chip_cert_size);
// 		if(OPTIGA_LIB_SUCCESS != status)
// 		{
// 			break;
// 		}
//
// 		// Verify the certificate against the given CA
// 		status = pal_crypt_verify_certificate(optiga_ca_certificate, sizeof(optiga_ca_certificate), chip_cert, chip_cert_size);
// 		if(CRYPTO_LIB_OK != status)
// 		{
// 			break;
// 		}
//
// 		// Extract Public Key from the certificate
// 		status = pal_crypt_get_public_key(chip_cert, chip_cert_size, chip_pubkey, &chip_pubkey_size);
// 		if(CRYPTO_LIB_OK != status)
// 		{
// 			break;
// 		}
//
// 		//Certificate verification
//     	status = __authenticate_chip(chip_pubkey, chip_pubkey_size, chip_privkey_oid);
// 		if(OPTIGA_LIB_SUCCESS != status)
// 		{
// 			break;
// 		}
//
//     } while(FALSE);
//
//     return status;
// }

#endif // MODULE_ENABLE_ONE_WAY_AUTH

/**
* @}
*/
