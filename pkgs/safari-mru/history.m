#import "history.h"

@implementation MRUHistory
- (instancetype)init {
    if ((self = [super init])) _order = @[];
    return self;
}

- (void)observeTabs:(NSArray *)tabs selected:(id)selected {
    // Closing a tab or switching Tab Groups invalidates the held-key snapshot.
    if (self.cycle && ![[NSSet setWithArray:tabs] isEqualToSet:[NSSet setWithArray:self.cycle]]) {
        [self finish];
    }
    NSMutableArray *order = [NSMutableArray array];
    for (id tab in self.order) if ([tabs containsObject:tab]) [order addObject:tab];
    for (id tab in tabs) if (![order containsObject:tab]) [order addObject:tab];
    self.order = order;
    if (self.cycle && ![selected isEqual:self.selected]) [self finish];
    self.selected = selected;
    if (!self.cycle) [self finish];
}

- (id)stepBackward:(BOOL)backward {
    if (self.order.count < 2) return nil;
    if (!self.cycle) self.cycle = self.order;
    NSUInteger index = [self.cycle indexOfObject:self.selected];
    if (index == NSNotFound) index = 0;
    NSUInteger count = self.cycle.count;
    self.selected = self.cycle[(index + (backward ? count - 1 : 1)) % count];
    return self.selected;
}

- (void)finish {
    self.cycle = nil;
    if (!self.selected || ![self.order containsObject:self.selected]) return;
    NSMutableArray *order = [self.order mutableCopy];
    [order removeObject:self.selected];
    [order insertObject:self.selected atIndex:0];
    self.order = order;
}
@end
