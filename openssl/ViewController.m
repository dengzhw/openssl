//
//  ViewController.m
//  openssl
//
//  Created by deng on 2019/8/10.
//  Copyright © 2019年 deng. All rights reserved.
//

#import "ViewController.h"
#import "OpenSSLWrapper/OpenSSLResolver.h"

#define kBase64_PubKey @"kBase64_PubKey"
#define kBase64_PriKey @"kBase64_PriKey"

@interface ViewController ()
@property(copy,nonatomic)NSString *publicKeyBase64;
@property(copy,nonatomic)NSString *privateKeyBase64;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    [self generate];
}

/**
 1、 demo中所有的加解密都支持分段处理。
 
 2、 注意一下填充模式
 
 3、 私钥加密公钥解密只是为了演示可行性，要根据场景做调整使用
 
 4、 已增加单元测试，有需要的话可以多测试几次。
 
 5、格式化私钥到 pem 格式的时候，注意开头和结尾要用如下格式(PKCS#1)
 
 -----BEGIN RSA PRIVATE KEY-----
 
 -----END RSA PRIVATE KEY-----
 下面这种格式为 (PKCS#8)
 
 -----BEGIN PRIVATE KEY-----
 BASE64 ENCODED DATA
 -----END PRIVATE KEY-----
 PKCS#1结构仅为RSA设计。X509,SSL支持的算法不仅仅是RSA，因此产生了更具有通用性的PKCS#8
 
 https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 
 https://medium.com/@oyrxx/rsa秘钥介绍及openssl生成命令-d3fcc689513f
 */

-(void)generate{
    //生成本地密钥对
    RSA *_publicKey;
    RSA *_privateKey;
    while (1) {
        if ([OpenSSLResolver generateRSAKeyPairWithKeySize:2048 publicKey:&_publicKey privateKey:&_privateKey]) {
            
            self.publicKeyBase64 = [OpenSSLResolver base64EncodedStringKey:_publicKey isPubkey:YES];
            self.privateKeyBase64 = [OpenSSLResolver base64EncodedStringKey:_privateKey isPubkey:NO];
            
            NSString * pubkey = [OpenSSLResolver PEMKeyFromBase64:self.publicKeyBase64 isPubkey:YES];
            NSString * privkey = [OpenSSLResolver PEMKeyFromBase64:self.privateKeyBase64 isPubkey:NO];

            NSLog(@"\n私钥:\n%@",_privateKeyBase64);
            NSLog(@"\n公钥:\n%@",_publicKeyBase64);
            NSLog(@"\n公钥key:\n%@",pubkey);
            NSLog(@"\n私钥key:\n%@",privkey);

            if (_privateKeyBase64 && _publicKeyBase64) {
                NSUserDefaults *userDefault = [NSUserDefaults standardUserDefaults];
                [userDefault setObject:_publicKeyBase64 forKey:kBase64_PubKey];
                [userDefault setObject:_privateKeyBase64 forKey:kBase64_PriKey];
                
                break;
            }
        }
    }
}

@end
