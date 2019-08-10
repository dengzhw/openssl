//
//  OppenSSLX509Resolver.h
//  openssl
//
//  Created by deng on 2019/8/10.
//  Copyright © 2019年 deng. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OpenSSL.h"
NS_ASSUME_NONNULL_BEGIN

@interface OppenSSLX509Resolver : NSObject

-(X509*)loadCerWithPath:(NSString*)urlPath;

-(NSString *)GetX509Info:(X509*)cerfilepath withoption:(NSInteger)Number;

@end

NS_ASSUME_NONNULL_END

