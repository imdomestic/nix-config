#import "history.h"

static void check(BOOL condition, NSString *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message.UTF8String);
        exit(1);
    }
}

int main(void) {
    @autoreleasepool {
        MRUHistory *h = [[MRUHistory alloc] init];
        NSArray *tabs = @[@1, @2, @3, @4];
        [h observeTabs:tabs selected:@1];
        [h observeTabs:tabs selected:@3];
        [h observeTabs:tabs selected:@2];
        check([h.order isEqual:@[@2, @3, @1, @4]], @"manual selection records recency");
        check([[h stepBackward:NO] isEqual:@3], @"first Tab returns to last used");
        [h observeTabs:tabs selected:@3];
        check([[h stepBackward:NO] isEqual:@1], @"held Ctrl traverses the frozen order");
        check([[h stepBackward:YES] isEqual:@3], @"Shift reverses within the same cycle");
        [h finish];
        check([h.order isEqual:@[@3, @2, @1, @4]], @"release promotes only the final tab");
        check([[h stepBackward:NO] isEqual:@2], @"next gesture returns to its origin");
        [h finish];
        check([[h stepBackward:NO] isEqual:@3], @"separate quick taps toggle two tabs");
        [h finish];
        check([[h stepBackward:YES] isEqual:@4], @"reverse from idle selects least recent");
        [h finish];
        [h observeTabs:@[@4, @3, @2, @1] selected:@4];
        check([[h stepBackward:NO] isEqual:@3], @"dragging tabs preserves identity and recency");
        [h observeTabs:tabs selected:@1];
        check(h.cycle == nil && [h.order.firstObject isEqual:@1], @"mouse selection ends the held cycle");
        [h stepBackward:NO];
        [h observeTabs:@[@1, @2] selected:@1];
        check(h.cycle == nil && [h.order isEqual:@[@1, @2]], @"closing tabs discards stale cycle entries");
        [h observeTabs:@[@1, @2, @5] selected:@5];
        check([h.order isEqual:@[@5, @1, @2]], @"newly selected tab becomes most recent");
        [h observeTabs:@[@7, @8] selected:@8];
        check([h.order isEqual:@[@8, @7]], @"a different Tab Group has no stale identities");
        [h observeTabs:@[@8] selected:@8];
        check([h stepBackward:NO] == nil, @"one tab cannot start a cycle");
        [h observeTabs:@[] selected:nil];
        check(h.order.count == 0 && h.cycle == nil, @"empty window clears history");
        puts("MRU history tests passed");
    }
    return 0;
}
