//
//  OppenSSLX509Resolver.m
//  openssl
//
//  Created by deng on 2019/8/10.
//  Copyright © 2019年 deng. All rights reserved.
//

#import "OppenSSLX509Resolver.h"
#import "OpenSSL.h"

@interface OppenSSLX509Resolver()
@property(strong,nonatomic)NSMutableString *serialNumber;
@property(strong,nonatomic)NSMutableString *allCertsList;
@property(assign,nonatomic)long Version; //保存证书版本
@property(strong,nonatomic)NSMutableString *certInfo;
@property(strong,nonatomic)NSMutableString *certCN;
@property(copy,nonatomic)NSString *notBefore; //获取证书生效日期
@property(copy,nonatomic)NSString *notAfter;  //获取证书过期日期
@property(strong,nonatomic)NSMutableString *subjectstring;
@property(assign,nonatomic)EVP_PKEY *pubKey; //证书公钥


@end

@implementation OppenSSLX509Resolver

-(instancetype)init{
    self = [super init];
    if(self){
        _certInfo = [[NSMutableString alloc] init];
        _certCN = [[NSMutableString alloc]init];
        _serialNumber = [[NSMutableString alloc]init];
        _allCertsList = [[NSMutableString alloc]init];
        _subjectstring = [[NSMutableString alloc]init];
    }
    return self;
}


-(X509*)loadCerWithPath:(NSString*)urlPath{
    OpenSSL_add_all_algorithms();
    //    NSString *userFile = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"user.cer"];
    X509 *x509= X509_new ();
    [self loadCertWithPathUrl:urlPath withX509:x509];
    return x509;
}

-(void)loadCertWithPathUrl:(NSString*)path withX509:(X509*)x509{
    NSData * certData;
    unsigned char buf[ 4096 ],*p;
    int len;
    assert (path!= nil );
    // 读取证书文件
    certData=[ NSData dataWithContentsOfFile :path];
    assert (certData!= nil );
    len=(int)certData.length;
    // NSData-->uchar*
    [certData getBytes :( void *)buf length :len];
    // p-->buf[0]
    p=buf;
    // 对 buf 中的数据进行解码，并返回一个 X509 结构
    d2i_X509 (&x509,( const unsigned char **)&p,len);
}


-(NSString *)GetX509Info:(X509*)cerfilepath withoption:(NSInteger)Number{

    X509 *x509Cert = cerfilepath; //X509证书结构体
    ASN1_TIME *time; //保存证书有效期时间
    //获取证书版本
    self.Version = X509_get_version(x509Cert);
    
    //获取证书颁发者信息，X509_NAME结构体保存了多项信息，包括国家、组织、部门、通用名、mail等。
    X509_NAME *subject = [self readX509SubjectInfoWithX509:x509Cert];
    int countsubject = X509_NAME_entry_count(subject);
    NSLog(@"%@",@(countsubject));

    //循环读取各条目信息
    [self readX509MenuWithX509:x509Cert];
    
    //读取证书序列号
    [self getSerialNumWithX509:x509Cert];

    //获取证书生效日期
    time = X509_get_notBefore(x509Cert);
    //printf("Cert notBefore:%s\n",time->data);
    self.notBefore = [NSString stringWithFormat:@"%s",time->data];
    
    //获取证书过期日期
    time = X509_get_notAfter(x509Cert);
    //printf("Cert notAfter:%s\n",time->data);
    self.notAfter = [NSString stringWithFormat:@"%s",time->data];
    
    //获取证书公钥
    self.pubKey = X509_get_pubkey(x509Cert);
    
    
    X509_free(x509Cert);
#pragma x509 read end
    
    NSMutableString *finaldetail = [self readLastDetailInfo:Number];
    return finaldetail;
    
}


//获取证书序列号
-(ASN1_INTEGER*)getSerialNumWithX509:(X509 *)x509Cert{
    ASN1_INTEGER *Serial = NULL; //保存证书序列号
    [_allCertsList appendString:_certInfo];
    [_allCertsList appendString:@"|"];
    Serial = X509_get_serialNumber(x509Cert);//获取证书序列号
    //打印证书序列号
    //printf("serialNumber is: \n");
    
    for(int i = 0; i < Serial->length; i++){
        //printf("%02x", Serial->data[i]);
        [_serialNumber appendString:[NSString stringWithFormat:@"%02x",Serial->data[i]]];
        
    }
    [_allCertsList appendString:_serialNumber];
    return Serial;
    
}

-(X509_NAME*)readX509SubjectInfoWithX509:(X509 *)x509Cert{
    X509_NAME *subject = NULL; //X509_NAME结构体，保存证书拥有者信息
    subject = X509_get_subject_name(x509Cert);//获取证书主题信息
    
    X509_NAME_ENTRY *subjectEntry = X509_NAME_get_entry(subject,2);
    X509_NAME_ENTRY_get_object(subjectEntry);
    X509_NAME_ENTRY_get_data(subjectEntry);
    NSString *subjectstr = [NSString stringWithUTF8String:(char*)X509_NAME_ENTRY_get_data(subjectEntry)->data];
    NSLog(@"final test %@",subjectstr);
    return subject;
    
}


-(void)readX509MenuWithX509:(X509 *)x509Cert{

    X509_NAME_ENTRY *name_entry;
    X509_NAME *issuer = NULL; //X509_NAME结构体，保存证书颁发者信息
    int msginfoLen;
    unsigned char msginfo[1024];
    long Nid;

    //打印整个X509结构信息
    issuer = X509_get_issuer_name(x509Cert);
    
    int entriesNum = sk_X509_NAME_ENTRY_num(issuer->entries);
    //获取X509_NAME条目个数
    
    for(int i=0;i<entriesNum;i++){
        //获取第I个条目值
        name_entry = sk_X509_NAME_ENTRY_value(issuer->entries,i);
        Nid = OBJ_obj2nid(name_entry->object);
        //判断条目编码的类型
        NSLog(@" type is  %d",name_entry->value->type);
        NSString *tempstr;
        if(name_entry->value->type==V_ASN1_BMPSTRING)//把UTF8编码数据转化成可见字符
        {
            //ASN1_STRING_to_UTF8(mesre,name_entry->value);
            msginfoLen=name_entry->value->length;
            memcpy(msginfo,name_entry->value->data,msginfoLen);
            msginfo[msginfoLen]='\0';
            NSString *temptring = [NSString stringWithFormat:@"C=%s,",msginfo];
            
            NSString*pageSource = [self encodeToPercentEscapeString:temptring];
            
            NSString *dataGBK = [pageSource stringByRemovingPercentEncoding];
            tempstr = dataGBK;
            
        }
        else{
            tempstr = [NSString stringWithFormat:@"C=%s,",msginfo];
            msginfoLen=name_entry->value->length;
            memcpy(msginfo,name_entry->value->data,msginfoLen);
            msginfo[msginfoLen]='\0';
            
        }
        switch(Nid) {
                case NID_countryName://国家C
                //printf("issuer 's C:%s\n",msginfo);
                [_subjectstring appendString:[NSString stringWithFormat:@"C=%s,",msginfo]];
                break;
                case NID_stateOrProvinceName://省ST
                //printf("issuer 's ST:%s\n",msginfo);
                //[subjectstring appendString:[NSString stringWithFormat:@"ST=%s,",msginfo]];
                [_subjectstring appendString:tempstr];
                break;
                case NID_localityName://地区L
                //printf("issuer 's L:%s\n",msginfo);
                [_subjectstring appendString:[NSString stringWithFormat:@"L=%s,",msginfo]];
                break;
                case NID_organizationName://组织O
                //printf("issuer 's O:%s\n",msginfo);
                [_subjectstring appendString:[NSString stringWithFormat:@"O=%s,",msginfo]];
                break;
                case NID_organizationalUnitName://单位OU
                //printf("issuer 's OU:%s\n",msginfo);
                [_subjectstring appendString:[NSString stringWithFormat:@"OU=%s,",msginfo]];
                break;
                case NID_commonName://通用名CNx
                //printf("issuer 's CN:%s\n",msginfo);
                [_subjectstring appendString:[NSString stringWithFormat:@"CN=%s",msginfo]];
                break;
                case NID_pkcs9_emailAddress://Mail
                //printf("issuer 's emailAddress:%s\n",msginfo);
                break;
                
        }//end switch
        
    }
}

-(NSMutableString*)readLastDetailInfo:(NSInteger)Number{
    
    NSMutableString *finaldetail = [[NSMutableString alloc]init];
    NSString *detaiInfo =[[NSString alloc]init];
    
#warning rsaX509文件
    NSString *RSAX509File = @"";
    NSString *cerEntity = [[NSString alloc] initWithContentsOfFile:RSAX509File encoding:NSUTF8StringEncoding error:nil];
    
    NSMutableString *notAftertime = [[NSMutableString alloc]initWithString:@"20"];
    
    NSRange range = NSMakeRange (19, 1);
    
    switch (Number) {
            
            case 1:
            //[finaldetail appendString:@"Version is "];
            detaiInfo = [NSString stringWithFormat:@"%ld",_Version];
            [finaldetail appendString:detaiInfo];
            break;
            case 2:
            detaiInfo =_serialNumber;
            [finaldetail appendString:detaiInfo];
            break;
            case 3:
            //[finaldetail appendString:@"Issuer is "];
            detaiInfo =_certInfo;
            [finaldetail appendString:detaiInfo];
            break;
            case 4:
            //[finaldetail appendString:@"NotBefore "];
            [notAftertime appendString:_notBefore];
            [notAftertime insertString:@"-" atIndex:4];
            [notAftertime insertString:@"-" atIndex:7];
            [notAftertime insertString:@" " atIndex:10];
            [notAftertime insertString:@":" atIndex:13];
            [notAftertime insertString:@":" atIndex:16];
            [notAftertime replaceCharactersInRange:range withString:@""];
            [finaldetail appendString:notAftertime];
            break;
            case 5:
            //[finaldetail appendString:@"NotAfter "];
            [notAftertime appendString:_notAfter];
            [notAftertime insertString:@"-" atIndex:4];
            [notAftertime insertString:@"-" atIndex:7];
            [notAftertime insertString:@" " atIndex:10];
            [notAftertime insertString:@":" atIndex:13];
            [notAftertime insertString:@":" atIndex:16];
            [notAftertime replaceCharactersInRange:range withString:@""];
            [finaldetail appendString:notAftertime];
            break;
            
            case 6:
            //[finaldetail appendString:@"Cer Entity is \n"];
            [finaldetail appendString:cerEntity];
            break;
            
            case 7:
            [finaldetail appendString:_certCN];
            break;
            case 8:
            [finaldetail appendString:_subjectstring];
            break;
        default:
            break;
    }
    return finaldetail;
}

- (NSString *)encodeToPercentEscapeString:(NSString*)str{
    
    NSString *charactersToEscape = @"?!@#$^&%*+,:;='\"`<>()[]{}/\\| ";
    NSCharacterSet *allowedCharacters = [[NSCharacterSet characterSetWithCharactersInString:charactersToEscape] invertedSet];
    return  [str stringByAddingPercentEncodingWithAllowedCharacters:allowedCharacters];
    
}
@end
