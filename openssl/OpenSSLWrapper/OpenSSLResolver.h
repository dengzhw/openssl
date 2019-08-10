//
//  OpenSSLResolver.h
//  openssl
//
//  Created by deng on 2019/8/10.
//  Copyright © 2019年 deng. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OpenSSL.h"


NS_ASSUME_NONNULL_BEGIN
typedef enum {
    Rsa_PKCS1_PADDING       =   RSA_PKCS1_PADDING,
    Rsa_SSLV23_PADDING      =   RSA_SSLV23_PADDING,
    Rsa_NO_PADDING          =   RSA_NO_PADDING,
    Rsa_PKCS1_OAEP_PADDING  =   RSA_PKCS1_OAEP_PADDING,
    Rsa_X931_PADDING        =   RSA_X931_PADDING,
    /* EVP_PKEY_ only */
    Rsa_PKCS1_PSS_PADDING   =   RSA_PKCS1_PSS_PADDING,
    Rsa_PKCS1_PADDING_SIZE  =   RSA_PKCS1_PADDING_SIZE,
}RsaPaddingType;


@interface OpenSSLResolver : NSObject

+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey;

+ (RSA *)rsaFromBase64:(NSString *)base64Key isPubkey:(BOOL)isPubkey;

#pragma mark ---密钥格式转换
+ (RSA *)rsaFromPEM:(NSString *)KeyPEM isPubkey:(BOOL)isPubkey;
+ (NSString *)base64EncodedStringKey:(RSA *)rsaKey isPubkey:(BOOL)isPubkey;
+(NSString *)PEMKeyFromBase64:(NSString *)base64Key isPubkey:(BOOL)isPubkey;

#pragma mark ---加解密
+ (NSData *)encryptWithPublicKey:(RSA *)publicKey plainData:(NSData *)plainData padding:(RsaPaddingType)padding;
+ (NSData *)decryptWithPrivateKey:(RSA *)privateKey cipherData:(NSData *)cipherData padding:(RsaPaddingType)padding;

+ (NSData *)encryptWithPrivateRSA:(RSA *)privateKey plainData:(NSData *)plainData padding:(RsaPaddingType)padding;
+ (NSData *)decryptWithPublicKey:(RSA *)publicKey cipherData:(NSData *)cipherData padding:(RsaPaddingType)padding;

@end

NS_ASSUME_NONNULL_END
