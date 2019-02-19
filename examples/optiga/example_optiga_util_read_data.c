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
* \file example_optiga_util_read_data.c
*
* \brief   This file provides the example for reading data/metadata from OPTIGA using
*          #optiga_util_read_data and #optiga_util_read_metadata.
*
* \ingroup
* @{
*/

#include "optiga/optiga_util.h"
#include "mbedtls/x509_crt.h"
#include <stdio.h>
#include <inttypes.h>
#include <openssl/x509.h>
/**
 * The below example demonstrates read data/metadata functionalities
 *
 * Example for #optiga_util_read_data and #optiga_util_read_metadata
 *
 */
optiga_lib_status_t example_optiga_util_read_data(void)
{
    printf("Reading data...\n");
    uint16_t offset, bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[1024];

    optiga_lib_status_t return_status;

    do
    {
        //Read device end entity certificate from OPTIGA
        optiga_oid = eDEVICE_PUBKEY_CERT_IFX;
        offset = 0x00;
        bytes_to_read = sizeof(read_data_buffer);

        /**
         * 1. Read data from a data object (e.g. certificate data object)
         *    using optiga_util_read_data.
         */
        return_status = optiga_util_read_data(optiga_oid,
                                              offset,
                                              read_data_buffer,
                                              &bytes_to_read);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
      			//Reading the data object failed.
            printf("Could not read data\n");
            break;
        }
        X509 *x509ser;
        x509ser = d2i_X509(NULL, &read_data_buffer, bytes_to_read);

        // int32_t ret;
        // mbedtls_x509_crt mbedtls_cert;
        // mbedtls_x509_crt_init(&mbedtls_cert);
        // ret = mbedtls_x509_crt_parse_der(&mbedtls_cert, read_data_buffer, bytes_to_read);
        // printf("%" PRId32 "\n", ret);

        // for (int i=0; i<1024; i++) {
        //    // printf("%u ", public_key[i] );
        //     printf("%02X \t", read_data_buffer[i]);
        // }

        /**
         * Read metadata of a data object (e.g. certificate data object E0E0)
         * using optiga_util_read_data.
         */
        optiga_oid = eDEVICE_PUBKEY_CERT_IFX;
        bytes_to_read = sizeof(read_data_buffer);
        return_status = optiga_util_read_metadata(optiga_oid,
                                                  read_data_buffer,
                                                  &bytes_to_read);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
        	// Read metadate failed
          printf("Could not read metadata\n");
            break;
        }
        else {
            printf("Reading data & metadata complete.\n");
          // printf("%s",bytes_to_read,read_data_buffer);
        }

    } while(FALSE);

    return return_status;
}
