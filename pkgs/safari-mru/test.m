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
        NSArray *tabs = @[@1, @2, @3, @4, @5, @6, @7];
        [h observeTabs:tabs selected:@1];
        [h observeTabs:tabs selected:@3];
        [h observeTabs:tabs selected:@2];
        NSArray *before = @[@2, @3, @1, @4, @5, @6, @7];
        check([h.order isEqual:before], @"manual selection records recency");
        check([[h stepBackward:NO] isEqual:@3], @"first Tab returns to last used");
        check([h.selected isEqual:@2] && [h.order isEqual:before], @"choosing a candidate does not switch pages or change MRU");
        check([h.cycle isEqual:@[@2, @3, @1, @4, @5]], @"gesture contains the five most recent tabs including current");
        [h observeTabs:tabs selected:@2];
        check([[h stepBackward:NO] isEqual:@1], @"held Ctrl traverses the frozen order");
        check([[h stepBackward:YES] isEqual:@3], @"Shift reverses within the same cycle");
        id target = [h commit];
        check([target isEqual:@3] && [h.selected isEqual:@2] && [h.order isEqual:before], @"release returns a target without assuming activation succeeded");
        [h observeTabs:tabs selected:target];
        check([h.order isEqual:@[@3, @2, @1, @4, @5, @6, @7]], @"only successful final activation changes MRU");
        check([[h stepBackward:NO] isEqual:@2], @"next gesture returns to its origin");
        [h observeTabs:tabs selected:[h commit]];
        check([[h stepBackward:NO] isEqual:@3], @"separate quick taps toggle two tabs");
        [h observeTabs:tabs selected:[h commit]];
        before = h.order;
        check([[h stepBackward:YES] isEqual:@5], @"reverse wraps within recent five, not all open tabs");
        [h cancel];
        check(h.cycle == nil && [h.selected isEqual:@3] && [h.order isEqual:before], @"Escape cancels without activation or recency changes");
        for (NSUInteger i = 0; i < 5; i++) [h stepBackward:NO];
        check([[h commit] isEqual:@3], @"five forward steps wrap to the current page");
        [h stepBackward:NO];
        [h observeTabs:@[@7, @6, @5, @4, @3, @2, @1] selected:@3];
        check([h.candidate isEqual:@2] && [h.cycle isEqual:@[@3, @2, @1, @4, @5]], @"dragging tabs preserves the held snapshot");
        [h observeTabs:@[@1, @2, @3, @4, @5, @6] selected:@3];
        check(h.cycle != nil, @"closing a tab outside recent five does not cancel the gesture");
        [h observeTabs:tabs selected:@1];
        check(h.cycle == nil && [h.order.firstObject isEqual:@1], @"mouse selection ends the held cycle");
        [h stepBackward:NO];
        [h observeTabs:@[@1, @2] selected:@1];
        check(h.cycle == nil && [h.order isEqual:@[@1, @2]], @"closing tabs discards stale cycle entries");
        [h stepBackward:NO];
        [h commit];
        [h observeTabs:@[@1, @2] selected:@1];
        check([h.order isEqual:@[@1, @2]], @"failed activation does not promote a candidate");
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
