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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/pal/pal.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"

extern pal_status_t pal_gpio_init(void);
extern pal_status_t pal_gpio_deinit(void);
extern pal_status_t pal_init(void);
extern ifx_i2c_context_t ifx_i2c_context_0;
optiga_comms_t optiga_comms = {(void*)&ifx_i2c_context_0, NULL,NULL, OPTIGA_COMMS_SUCCESS};
uint16_t POID = 0;

/**
 * The below example demonstrates the signing of digest using
 * the Private key in OPTIGA Key store.
 *
 * Example for #optiga_crypt_ecdsa_sign
 *
 */

static int32_t __optiga_init(void)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;

	do
	{
		int32_t gpio_status = pal_gpio_init();

		printf("gpio init status 0x%04X\n\r", gpio_status);
		gpio_status = pal_os_event_init();
		printf("os_event_init status 0x%04X\n\r", gpio_status);
		int32_t pal_status = pal_init();
		if (pal_status != PAL_STATUS_SUCCESS) {
			printf( "Failure: pal_init(): 0x%04X\n\r", pal_status);
			break;
		}

		status = optiga_util_open_application(&optiga_comms);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			printf( "Failure: optiga_util_open_application(): 0x%04X\n\r", status);
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while(0);

	return status;
}

//int32_t main(int argc, char ** argv)
//optiga_lib_status_t example_optiga_crypt_ecdsa_sign(void)
int32_t sign(void)
{
    uint8_t digest [] = {
        // Digest to be signed..
        // Size of digest to be chosen based on Curve
        0x61, 0xC7, 0xDE, 0xF9, 0x0F, 0xD5, 0xCD, 0x7A,
        0x8B, 0x7A, 0x36, 0x41, 0x04, 0xE0, 0x0D, 0x82,
        0x38, 0x46, 0xBF, 0xB7, 0x70, 0xEE, 0xBF, 0x8F,
        0x40, 0x25, 0x2E, 0x0A, 0x21, 0x42, 0xAF, 0x9C,
    };

    uint8_t signature [80];     //To store the signture generated
    uint16_t signature_length = sizeof(signature);

    /* Initialise OPTIGA(TM) Trust X */
    if (__optiga_init() != OPTIGA_LIB_SUCCESS)
    {
      printf("OPTIGA Open Application failed.\n");
      return -1;
    }
    printf("OPTIGA(TM) Trust X initialized.\n");


    optiga_lib_status_t return_status;

    do
    {

        /**
         * Sign the digest -
         *       - Use Private key from Key Store ID E0F0
         */
        return_status = optiga_crypt_ecdsa_sign(digest,
                                                sizeof(digest),
						                                    OPTIGA_KEY_STORE_ID_E0F0,
                                                signature,
                                                &signature_length);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
 	    printf("Failed to sign: 0x%04X\n", return_status);
		// Signature generation failed
            break;
        }
	else {
	    printf("Successfully signed \n");
	}


    } while(FALSE);

    return return_status;
}

/**
* @}
*/
