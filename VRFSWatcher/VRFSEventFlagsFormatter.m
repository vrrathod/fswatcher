//
//  VRFSEventFlagsFormatter.m
//  VRFSWatcher
//
//  Created by Viral on 3/28/13.
//  Copyright (c) 2013 Symantec. All rights reserved.
//

#import "VRFSEventFlagsFormatter.h"

@implementation VRFSEventFlagsFormatter

- (NSString *)stringForObjectValue:(id)anObject
{
    if (![anObject isKindOfClass:[NSNumber class]]) {
        return nil;
    }
    
    return [[self class] stringForEventStringFlags:[anObject unsignedIntValue]];
}

- (BOOL)getObjectValue:(id *)obj forString:(NSString *)string errorDescription:(NSString  **)error
{
    *obj = @0;
    
    if (error)
    {
        *error = @"not-supported";
    }
    
    return NO;
}


///////////////////////////////////////////////////////////////////////////////////////

+ (NSString *) stringForEventStringFlags:(FSEventStreamEventFlags) flag
{
    NSMutableString *strFlags = [NSMutableString new];
    
    [strFlags appendFormat:@"[0x%08X] ", flag];
    
    if ( flag & kFSEventStreamEventFlagNone ) { [strFlags appendFormat:@"%@ ,", @"None"]; }
    if ( flag & kFSEventStreamEventFlagMustScanSubDirs) { [strFlags appendFormat:@"%@ ,", @"MustScanSubDirs"]; }
    if ( flag & kFSEventStreamEventFlagUserDropped)  { [strFlags appendFormat:@"%@ ,", @"UserDropped"]; }
    if ( flag & kFSEventStreamEventFlagKernelDropped) { [strFlags appendFormat:@"%@ ,", @"KernelDropped"]; }
    if ( flag & kFSEventStreamEventFlagEventIdsWrapped)  { [strFlags appendFormat:@"%@ ,", @"EventIdsWrapped"]; }
    if ( flag & kFSEventStreamEventFlagHistoryDone) { [strFlags appendFormat:@"%@ ,", @"HistoryDone"]; }
    if ( flag & kFSEventStreamEventFlagRootChanged)  { [strFlags appendFormat:@"%@ ,", @"RootChanged"]; }
    if ( flag & kFSEventStreamEventFlagMount) { [strFlags appendFormat:@"%@ ,", @"Mount"]; }
    if ( flag & kFSEventStreamEventFlagUnmount )  { [strFlags appendFormat:@"%@ ,", @"Unmount"]; }
    
    // following are available 10.7 onwards
    if ( flag & kFSEventStreamEventFlagItemCreated) { [strFlags appendFormat:@"%@ ,", @"Created"]; }
    if ( flag & kFSEventStreamEventFlagItemRemoved)  { [strFlags appendFormat:@"%@ ,", @"Removed"]; }
    if ( flag & kFSEventStreamEventFlagItemInodeMetaMod) { [strFlags appendFormat:@"%@ ,", @"InodeMetaMod"]; }
    if ( flag & kFSEventStreamEventFlagItemRenamed)  { [strFlags appendFormat:@"%@ ,", @"Renamed"]; }
    if ( flag & kFSEventStreamEventFlagItemModified)  { [strFlags appendFormat:@"%@ ,", @"Modified"]; }
    if ( flag & kFSEventStreamEventFlagItemFinderInfoMod) { [strFlags appendFormat:@"%@ ,", @"FinderInfoMod"]; }
    if ( flag & kFSEventStreamEventFlagItemChangeOwner)  { [strFlags appendFormat:@"%@ ,", @"ChangeOwner"]; }
    if ( flag & kFSEventStreamEventFlagItemXattrMod) { [strFlags appendFormat:@"%@ ,", @"XattrMod"]; }
    if ( flag & kFSEventStreamEventFlagItemIsFile)  { [strFlags appendFormat:@"%@ ,", @"IsFile"]; }
    if ( flag & kFSEventStreamEventFlagItemIsDir) { [strFlags appendFormat:@"%@ ,", @"IsDir"]; }
    if ( flag & kFSEventStreamEventFlagItemIsSymlink)  { [strFlags appendFormat:@"%@ ,", @"IsSymlink"]; }
    
    
    NSString *valueToReturn = [NSString stringWithString:strFlags];
    
    return valueToReturn;
}



@end
