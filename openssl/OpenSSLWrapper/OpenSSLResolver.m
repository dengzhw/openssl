//
//  OpenSSLResolver.m
//  openssl
//
//  Created by deng on 2019/8/10.
//  Copyright © 2019年 deng. All rights reserved.
//

#import "OpenSSLResolver.h"

@implementation OpenSSLResolver

#pragma mark ---生成密钥对
+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey{
    if (keySize == 512 || keySize == 1024 || keySize == 2048) {
        /* 产生RSA密钥 */
        RSA *rsa = RSA_new();
        BIGNUM* e = BN_new();
        /* 设置随机数长度 */
        BN_set_word(e, 65537);
        /* 生成RSA密钥对 RSA_generate_key_ex()新版本方法 */
        RSA_generate_key_ex(rsa, keySize, e, NULL);
        if (rsa) {
            *publicKey = RSAPublicKey_dup(rsa);
            *privateKey = RSAPrivateKey_dup(rsa);
            return YES;
        }
    }
    return NO;
}
+ (NSString *)base64EncodedStringKey:(RSA *)rsaKey isPubkey:(BOOL)isPubkey{
    if (!rsaKey) {
        return nil;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    
    if (isPubkey) {
        PEM_write_bio_RSA_PUBKEY(bio, rsaKey);
    }else{
        //此方法生成的是pkcs1格式的,IOS中需要pkcs8格式的,因此通过PEM_write_bio_PrivateKey 方法生成
        // PEM_write_bio_RSAPrivateKey(bio, rsaKey, NULL, NULL, 0, NULL, NULL);
        EVP_PKEY* key = NULL;
        key = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(key, rsaKey);
        PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    NSString *res = [NSString stringWithUTF8String:bptr->data];
    //将PEM格式转换为base64格式
    return [self base64EncodedStringFromPEM:res];
}

+ (NSString *)base64EncodedStringFromPEM:(NSString *)PEMFormat{
    return [[[PEMFormat componentsSeparatedByString:@"-----"] objectAtIndex:2] stringByReplacingOccurrencesOfString:@"\n" withString:@""];
}
+(NSString *)PEMKeyFromBase64:(NSString *)base64Key isPubkey:(BOOL)isPubkey{
    NSMutableString *result = [NSMutableString string];
    if (isPubkey) {
        [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    }else{
        [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    }
    int count = 0;
    for (int i = 0; i < [base64Key length]; ++i) {
        unichar c = [base64Key characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    if (isPubkey) {
        [result appendString:@"\n-----END PUBLIC KEY-----"];
    }else{
        [result appendString:@"\n-----END RSA PRIVATE KEY-----"];
    }
    return result;
}
+ (RSA *)rsaFromBase64:(NSString *)base64Key isPubkey:(BOOL)isPubkey{
    NSString *result = [self PEMKeyFromBase64:base64Key isPubkey:isPubkey];
    return [self rsaFromPEM:result isPubkey:isPubkey];
}

#pragma mark ---密钥格式转换
+ (RSA *)rsaFromPEM:(NSString *)KeyPEM isPubkey:(BOOL)isPubkey{
    const char *buffer = [KeyPEM UTF8String];
    BIO *keyBio = BIO_new_mem_buf(buffer, (int)strlen(buffer));
    RSA *rsa;
    if (isPubkey) {
        rsa = PEM_read_bio_RSA_PUBKEY(keyBio, NULL, NULL, NULL);
    }else{
        rsa = PEM_read_bio_RSAPrivateKey(keyBio, NULL, NULL, NULL);
    }
    BIO_free_all(keyBio);
    return rsa;
}




#pragma mark ---加解密
+ (NSData *)encryptWithPublicKey:(RSA *)publicKey plainData:(NSData *)plainData padding:(RsaPaddingType)padding{
    int paddingSize = 0;
    if (padding == Rsa_PKCS1_PADDING) {
        paddingSize = Rsa_PKCS1_PADDING_SIZE;
    }
    
    int publicRSALength = RSA_size(publicKey);
    double totalLength = [plainData length];
    int blockSize = publicRSALength - paddingSize;
    int blockCount = ceil(totalLength / blockSize);
    size_t publicEncryptSize = publicRSALength;
    NSMutableData *encryptDate = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        int dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [plainData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        char *publicEncrypt = malloc(publicRSALength);
        memset(publicEncrypt, 0, publicRSALength);
        const unsigned char *str = [dataSegment bytes];
        int r = RSA_public_encrypt(dataSegmentRealSize,str,(unsigned char*)publicEncrypt,publicKey,padding);
        if (r < 0) {
            free(publicEncrypt);
            return nil;
        }
        NSData *encryptData = [[NSData alloc] initWithBytes:publicEncrypt length:publicEncryptSize];
        [encryptDate appendData:encryptData];
        
        free(publicEncrypt);
    }
    return encryptDate;
}

+ (NSData *)decryptWithPrivateKey:(RSA *)privateKey cipherData:(NSData *)cipherData padding:(RsaPaddingType)padding{
    
    if (!privateKey) {
        return nil;
    }
    if (!cipherData) {
        return nil;
    }
    int privateRSALenght = RSA_size(privateKey);
    double totalLength = [cipherData length];
    int blockSize = privateRSALenght;
    int blockCount = ceil(totalLength / blockSize);
    NSMutableData *decrypeData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        long dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [cipherData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        const unsigned char *str = [dataSegment bytes];
        unsigned char *privateDecrypt = malloc(privateRSALenght);
        memset(privateDecrypt, 0, privateRSALenght);
        int ret = RSA_private_decrypt(privateRSALenght,str,privateDecrypt,privateKey,padding);
        if(ret >=0){
            NSData *data = [[NSData alloc] initWithBytes:privateDecrypt length:ret];
            [decrypeData appendData:data];
        }
        free(privateDecrypt);
    }
    
    return decrypeData;
}

+ (NSData *)encryptWithPrivateRSA:(RSA *)privateKey plainData:(NSData *)plainData padding:(RsaPaddingType)padding{
    
    if (!privateKey) {
        return nil;
    }
    if (!plainData) {
        return nil;
    }
    int paddingSize = 0;
    if (padding == Rsa_PKCS1_PADDING) {
        paddingSize = Rsa_PKCS1_PADDING_SIZE;
    }
    
    int privateRSALength = RSA_size(privateKey);
    double totalLength = [plainData length];
    int blockSize = privateRSALength - paddingSize;
    int blockCount = ceil(totalLength / blockSize);
    size_t privateEncryptSize = privateRSALength;
    NSMutableData *encryptDate = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        int dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [plainData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        char *privateEncrypt = malloc(privateRSALength);
        memset(privateEncrypt, 0, privateRSALength);
        const unsigned char *str = [dataSegment bytes];
        int r = RSA_private_encrypt(dataSegmentRealSize,str,(unsigned char*)privateEncrypt,privateKey,padding);
        if (r < 0) {
            free(privateEncrypt);
            return nil;
        }
        
        NSData *encryptData = [[NSData alloc] initWithBytes:privateEncrypt length:privateEncryptSize];
        [encryptDate appendData:encryptData];
        
        free(privateEncrypt);
    }
    return encryptDate;
    
}

+ (NSData *)decryptWithPublicKey:(RSA *)publicKey cipherData:(NSData *)cipherData padding:(RsaPaddingType)padding{
    if (!publicKey) {
        return nil;
    }
    if (!cipherData) {
        return nil;
    }
    
    int publicRSALenght = RSA_size(publicKey);
    double totalLength = [cipherData length];
    int blockSize = publicRSALenght;
    int blockCount = ceil(totalLength / blockSize);
    NSMutableData *decrypeData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        long dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [cipherData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        const unsigned char *str = [dataSegment bytes];
        unsigned char *publicDecrypt = malloc(publicRSALenght);
        memset(publicDecrypt, 0, publicRSALenght);
        int ret = RSA_public_decrypt(publicRSALenght,str,publicDecrypt,publicKey,padding);
        if(ret < 0){
            free(publicDecrypt);
            return nil ;
        }
        NSData *data = [[NSData alloc] initWithBytes:publicDecrypt length:ret];
        if (padding == Rsa_NO_PADDING) {
            Byte flag[] = {0x00};
            NSData *startData = [data subdataWithRange:NSMakeRange(0, 1)];
            if ([[startData description] isEqualToString:@"<00>"]) {
                NSRange startRange = [data rangeOfData:[NSData dataWithBytes:flag length:1] options:NSDataSearchBackwards range:NSMakeRange(0, data.length)];
                NSUInteger s = startRange.location + startRange.length;
                if (startRange.location != NSNotFound && s < data.length) {
                    data = [data subdataWithRange:NSMakeRange(s, data.length - s)];
                }
            }
        }
        [decrypeData appendData:data];
        
        free(publicDecrypt);
    }
    return decrypeData;
}
@end
