#import "history.h"

@implementation MRUHistory
- (instancetype)init {
    if ((self = [super init])) _order = @[];
    return self;
}

- (void)observeTabs:(NSArray *)tabs selected:(id)selected {
    // Only removal of a gesture candidate invalidates the frozen recent-five list.
    for (id tab in self.cycle) {
        if (![tabs containsObject:tab]) {
            [self cancel];
            break;
        }
    }
    NSMutableArray *order = [NSMutableArray array];
    for (id tab in self.order) if ([tabs containsObject:tab]) [order addObject:tab];
    for (id tab in tabs) if (![order containsObject:tab]) [order addObject:tab];
    self.order = order;
    if (self.cycle && ![selected isEqual:self.selected]) [self cancel];
    self.selected = selected;
    if (!self.cycle && selected && [self.order containsObject:selected]) {
        [order removeObject:selected];
        [order insertObject:selected atIndex:0];
        self.order = order;
    }
}

- (id)stepBackward:(BOOL)backward {
    if (self.order.count < 2) return nil;
    if (!self.cycle) {
        self.cycle = [self.order subarrayWithRange:NSMakeRange(0, MIN(5, self.order.count))];
        self.candidate = self.selected;
    }
    NSUInteger index = [self.cycle indexOfObject:self.candidate];
    if (index == NSNotFound) index = 0;
    NSUInteger count = self.cycle.count;
    self.candidate = self.cycle[(index + (backward ? count - 1 : 1)) % count];
    return self.candidate;
}

- (id)commit {
    id target = self.cycle ? self.candidate : nil;
    [self cancel];
    return target;
}

- (void)cancel {
    self.cycle = nil;
    self.candidate = nil;
}
@end
