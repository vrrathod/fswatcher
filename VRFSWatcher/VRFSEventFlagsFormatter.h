//
//  VRFSEventFlagsFormatter.h
//  VRFSWatcher
//
//  Created by Viral on 3/28/13.
//  Copyright (c) 2013 Symantec. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VRFSEventFlagsFormatter : NSFormatter

+ (NSString *) stringForEventStringFlags:(FSEventStreamEventFlags) flags;

@end
