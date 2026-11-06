#import <Foundation/Foundation.h>
#import <Security/Security.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        NSURL *url = [NSURL fileURLWithPath:@(argv[1]) isDirectory:YES];
        SecStaticCodeRef code = NULL;
        OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code);
        if (status != errSecSuccess) {
            fprintf(stderr, "Cannot load app signature: %d\n", (int)status);
            return 1;
        }
        CFErrorRef error = NULL;
        status = SecStaticCodeCheckValidityWithErrors(code,
            kSecCSStrictValidate | kSecCSCheckAllArchitectures, NULL, &error);
        if (status != errSecSuccess) {
            NSError *detail = CFBridgingRelease(error);
            fprintf(stderr, "Invalid app signature (%d): %s\n", (int)status, detail.description.UTF8String);
            CFRelease(code);
            return 1;
        }
        CFDictionaryRef rawInfo = NULL;
        status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &rawInfo);
        CFRelease(code);
        NSDictionary *info = CFBridgingRelease(rawInfo);
        NSString *identifier = info[(__bridge NSString *)kSecCodeInfoIdentifier];
        NSDictionary *plist = info[(__bridge NSString *)kSecCodeInfoPList];
        NSString *expected = @"com.imdomestic.safari-mru";
        if (status != errSecSuccess || ![identifier isEqual:expected] ||
            ![plist[@"CFBundleIdentifier"] isEqual:expected]) {
            fprintf(stderr, "Signing identifier and sealed Info.plist must both identify Safari MRU\n");
            return 1;
        }
        puts("App signature, signing identifier, and sealed Info.plist verified");
    }
    return 0;
}
