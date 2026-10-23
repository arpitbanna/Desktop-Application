#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(TrustRootSecurityModule, NSObject)

RCT_EXTERN_METHOD(generateDeviceKey:(NSString *)alias
                  algorithm:(NSString *)algorithm
                  preferStrongBox:(BOOL)preferStrongBox
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getKeyMetadata:(NSString *)alias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getHardwareSecurityLevel:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signPayload:(NSString *)alias
                  canonicalString:(NSString *)canonicalString
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encryptPayload:(NSString *)payloadBase64
                  payloadType:(NSString *)payloadType
                  recipientPublicKeyPem:(NSString *)recipientPublicKeyPem
                  recipientKeyId:(NSString *)recipientKeyId
                  deviceKeyAlias:(NSString *)deviceKeyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deleteDeviceKey:(NSString *)alias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(rotateDeviceKey:(NSString *)oldAlias
                  preferStrongBox:(BOOL)preferStrongBox
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getDiagnostics:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
