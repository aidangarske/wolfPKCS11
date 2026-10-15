/* default_devid_pin_kdf_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
    #include <dlfcn.h>
#endif

#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
        #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
        #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif

#if defined(WOLF_CRYPTO_CB) && defined(WOLFPKCS11_DEFAULT_DEVID) && \
    defined(WOLFPKCS11_PIN_KDF_SOFTWARE) && defined(WOLFPKCS11_PBKDF2)

#define TEST_DEVID WOLFPKCS11_DEFAULT_DEVID

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static int callbackCalls;
static int pinHashCalls;
static int cipherCalls;

static int test_crypto_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)ctx;

    if (devId != TEST_DEVID || info == NULL)
        return BAD_FUNC_ARG;

    callbackCalls++;
    if (info->algo_type == WC_ALGO_TYPE_HMAC ||
        info->algo_type == WC_ALGO_TYPE_HASH) {
        pinHashCalls++;
    }
    if (info->algo_type == WC_ALGO_TYPE_CIPHER)
        cipherCalls++;

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

static CK_RV get_function_list(void)
{
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList getFunctionList;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "FAIL: dlopen: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    getFunctionList = (CK_C_GetFunctionList)dlsym(dlib,
        "C_GetFunctionList");
    if (getFunctionList == NULL)
        return CKR_GENERAL_ERROR;
    return getFunctionList(&funcList);
#else
    return C_GetFunctionList(&funcList);
#endif
}

static void close_library(void)
{
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV initialize_library(CK_SLOT_ID* slot)
{
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slots[4];
    CK_ULONG slotCount = sizeof(slots) / sizeof(slots[0]);
    CK_RV rv;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slots, &slotCount);
    if (rv == CKR_OK && slotCount == 0U)
        rv = CKR_SLOT_ID_INVALID;
    if (rv == CKR_OK)
        *slot = slots[0];

    return rv;
}

static CK_RV initialize_token(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR soPin[] = "password123456";
    CK_UTF8CHAR userPin[] = "wolfpkcs11-test";
    CK_RV rv;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1U, label);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1U);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1U);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }

    return rv;
}

static CK_RV exercise_device_cipher(CK_SLOT_ID slot)
{
    CK_UTF8CHAR userPin[] = "wolfpkcs11-test";
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BYTE keyValue[16] = { 0 };
    CK_BYTE iv[16] = { 0 };
    CK_BYTE plain[16] = { 0 };
    CK_BYTE cipher[32];
    CK_ULONG cipherLen = sizeof(cipher);
    CK_MECHANISM mechanism = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) },
        { CKA_VALUE, keyValue, sizeof(keyValue) }
    };
    CK_RV rv;

    rv = funcList->C_OpenSession(slot,
        CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, userPin,
            sizeof(userPin) - 1U);
    }
    if (rv == CKR_OK && pinHashCalls != 0) {
        fprintf(stderr, "FAIL: PIN PBKDF2 reached device %d\n", TEST_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, attrs,
            sizeof(attrs) / sizeof(attrs[0]), &key);
    }
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(session, &mechanism, key);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, plain, sizeof(plain), cipher,
            &cipherLen);
    if (rv == CKR_OK && cipherCalls == 0) {
        fprintf(stderr, "FAIL: AES did not reach device %d\n", TEST_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }

    if (key != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, key);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }

    return rv;
}

int main(void)
{
    CK_SLOT_ID slot = 0;
    CK_RV rv;
    int ret;
    int deviceRegistered = 0;

    rv = get_function_list();
    if (rv == CKR_OK)
        rv = initialize_library(&slot);
    if (rv == CKR_OK) {
        ret = wc_CryptoCb_RegisterDevice(TEST_DEVID, test_crypto_cb, NULL);
        if (ret != 0) {
            fprintf(stderr, "FAIL: register device: %d\n", ret);
            rv = CKR_DEVICE_ERROR;
        }
        else {
            deviceRegistered = 1;
        }
    }
    if (rv == CKR_OK)
        rv = initialize_token(slot);
    if (rv == CKR_OK)
        rv = exercise_device_cipher(slot);

    if (deviceRegistered)
        wc_CryptoCb_UnRegisterDevice(TEST_DEVID);
    if (funcList != NULL)
        (void)funcList->C_Finalize(NULL);
    close_library();

    if (rv != CKR_OK) {
        fprintf(stderr, "FAIL: PKCS11 operation: 0x%lx\n",
            (unsigned long)rv);
        return 1;
    }
    if (callbackCalls == 0) {
        fprintf(stderr, "FAIL: device callback was never called\n");
        return 1;
    }

    printf("PASS: slot crypto used device %d and PIN PBKDF2 stayed local\n",
        TEST_DEVID);
    return 0;
}

#else

int main(void)
{
    printf("SKIP: default device/PIN KDF configuration not enabled\n");
    return 0;
}

#endif
