#import <Foundation/Foundation.h>

// Tokens are retained AXUIElements in the app and opaque identities in the tests.
@interface MRUHistory : NSObject
@property(nonatomic, copy) NSArray *order;
@property(nonatomic, copy) NSArray *cycle;
@property(nonatomic, strong) id selected;
- (void)observeTabs:(NSArray *)tabs selected:(id)selected;
- (id)stepBackward:(BOOL)backward;
- (void)finish;
@end
