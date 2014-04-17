//
//  VRMainController.m
//  VRFSWatcher
//
//  Created by Viral on 3/25/13.
//  Copyright (c) 2013 Symantec. All rights reserved.
//

#import "VRMainController.h"

@implementation VRMainController

//-------------------------- INITIALIZATION ------------
- (id) init
{
	self = [super init];
    if (self != nil) {
        fileManager = [NSFileManager defaultManager];
        arrDFS = [NSMutableArray new];

        scanFinished = true;
        shouldScan = true;
        //TODO: Add init for all the other column array here
    }
	return self;
}

- (void) awakeFromNib
{
    [self registerDefaults];
    
    [_predicateEditor addRow:self];
    
    appStartedTimestamp = [NSDate date];
    
//    lastEventId = [[NSUserDefaults standardUserDefaults] objectForKey:@"lastEventId"];
    lastEventId = [NSNumber numberWithLongLong:kFSEventStreamEventIdSinceNow];
    
    [_pathToWatch setObjectValue:NSHomeDirectory()];
    
    NSString* savedPredicate = [[NSUserDefaults standardUserDefaults] objectForKey:@"predicateValue"];
    if (savedPredicate)
    {
        [_predicateEditor setObjectValue:[NSPredicate predicateWithFormat:savedPredicate]];
    }
    
    // initialize mutable array to get existing sort descriptor prototype
    NSMutableArray *tableSortDescriptorPrototype = [NSMutableArray new];
    
    // for each column,
    for(NSTableColumn *tablecolumn in [_table tableColumns])
    {
        // get existing sort descriptor prototype
        NSSortDescriptor* sortDescriptor = [tablecolumn sortDescriptorPrototype];
        if (sortDescriptor)
        {
            // for a valid prototype, add it to array
            [tableSortDescriptorPrototype addObject:sortDescriptor];
        }
    }
    
    // if we find any sort descriptor prototype,
    if ([tableSortDescriptorPrototype count] )
    {
        // then we set them on table.
        [_table setSortDescriptors:tableSortDescriptorPrototype];
    }
    
    [self initializeEventStream];
    
    [self clearEvents:nil];
    
    // lets start counting files
    [self performSelectorInBackground:@selector(performFileScanInBackground:) withObject:[[_pathToWatch URL] path]];
}

- (void) registerDefaults
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    NSArray* objects = [NSArray arrayWithObjects:
                        [NSNumber numberWithUnsignedLongLong:kFSEventStreamEventIdSinceNow],
                        @"path contains '/'",
                        nil];
    NSArray* keys = [NSArray arrayWithObjects:@"lastEventId", @"predicateValue", nil];
    
    NSDictionary *appDefaults = [NSDictionary
	                             dictionaryWithObjects: objects
	                             forKeys: keys];
    
    
	[defaults registerDefaults:appDefaults];
}
//-------------------------- TERMINATION ------------
- (NSApplicationTerminateReply)applicationShouldTerminate: (NSApplication *)app
{
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
	[defaults setObject:lastEventId forKey:@"lastEventId"];
    [defaults setObject:[[_predicateEditor predicate] description ] forKey:@"predicateValue"];
	[defaults synchronize];
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    return NSTerminateNow;
}

/////////////////////////////////////////////////////////////////////////////////////////////
- (void) initializeEventStream
{
    //    NSString *myPath = NSHomeDirectory();
    //    NSString *myPath = @"/Users/viral/temp";
    NSString *myPath = [[_pathToWatch URL] path];
    NSArray *pathsToWatch = [NSArray arrayWithObject:myPath];
    void *appPointer = (__bridge void *) self;
    FSEventStreamContext context = {0, appPointer, NULL, NULL, NULL};
    NSTimeInterval latency = 0.5;
    stream = FSEventStreamCreate(NULL,
                                 &fsevents_callback,
                                 &context,
                                 (__bridge CFArrayRef) pathsToWatch,
                                 [lastEventId unsignedLongLongValue],
                                 (CFAbsoluteTime) latency,
                                 kFSEventStreamCreateFlagUseCFTypes
                                 | kFSEventStreamCreateFlagFileEvents
                                 );
    
    FSEventStreamScheduleWithRunLoop(stream,
                                     CFRunLoopGetCurrent(),
                                     kCFRunLoopDefaultMode);
    
    //    FSEventStreamStart(stream);
}

- (void) uninitializeEventStream
{
    // stop watching
    [self startWatchingStream:false];
    
    // invalidate
    FSEventStreamInvalidate(stream);
    
    // release
    FSEventStreamRelease(stream);
}

-(void) startWatchingStream: (BOOL) shouldStart
{
    if (shouldStart)
    {
        FSEventStreamStart(stream);
    }
    else
    {
        FSEventStreamStop(stream);
    }
}


- (void)updateLastEventId: (uint64_t) eventId
{
	lastEventId = [NSNumber numberWithUnsignedLongLong:eventId];
}

- (NSNumber*) numberOfFsChanges
{
    return  [NSNumber numberWithUnsignedInteger:[[_eventsArrayController arrangedObjects] count]];
}

- (NSNumber*) numberOfFiles
{
    return  [NSNumber numberWithUnsignedInteger:[arrDFS  count]];
}

//------------------------------------------------------------------------------
- (Boolean) shouldScan
{
    @synchronized(self)
    {
        return shouldScan;
    }
}

- (void) setShouldScan:(Boolean) setScan
{
    @synchronized(self)
    {
        shouldScan = setScan;
    }
}

//------------------------------------------------------------------------------
- (Boolean) scanFinished
{    
    @synchronized(self)
    {
        return scanFinished;
    }
}

- (void) setScanFinished:(Boolean) setScanFinished
{
    @synchronized(self)
    {
        scanFinished = setScanFinished;
    }
}


//------------------------------------------------------------------------------
- (IBAction)applyPredicate:(id)sender
{
    [self willChangeValueForKey:@"numberOfFsChanges"];
    [_eventsArrayController setFilterPredicate: [_predicateEditor predicate]];
    [self didChangeValueForKey:@"numberOfFsChanges"];
}

- (IBAction)resetEvents:(id)sender
{
    [self willChangeValueForKey:@"numberOfFsChanges"];
    [_eventsArrayController setFilterPredicate:nil];
    [self didChangeValueForKey:@"numberOfFsChanges"];
    [_predicateEditor setObjectValue:[NSPredicate predicateWithFormat:@"path like '*'"]];
}

- (void) processPath: (NSString*) path withFlags:(FSEventStreamEventFlags) flag andEventID:(FSEventStreamEventId)eventId
{
    NSMutableDictionary *row = [NSMutableDictionary dictionaryWithObjectsAndKeys:path, @"path",
                                [path lastPathComponent], @"name",
                                [path pathExtension], @"extension",
                                [NSNumber numberWithUnsignedInt:flag], @"flags",
                                [NSNumber numberWithLongLong:eventId], @"eventID",
                                nil];
    
    if ([_resetFilterOnIncomingEvent state])
    {
        [_eventsArrayController setFilterPredicate:nil];
    }
    
    [self willChangeValueForKey:@"numberOfFsChanges"];
    [_eventsArrayController addObject:row];
    [self didChangeValueForKey:@"numberOfFsChanges"];
    [self updateLastEventId:eventId];
    
}
/////////////////////////////////////////////////////////////////////////////////////////

- (IBAction)toggleWatch:(id)sender
{
    [self startWatchingStream:[sender state]];
}

- (IBAction)changePathToWatch:(id)sender
{
    [_btnWatch setState:0];
    [self uninitializeEventStream];
    
    NSLog(@"New location to watch : %@...", [[_pathToWatch URL] path]);
    [self initializeEventStream];

    [self performSelectorInBackground:@selector(performFileScanInBackground:) withObject:[[_pathToWatch URL] path]];
}

- (IBAction)clearEvents:(id)sender
{
    NSRange indexRange = NSMakeRange(0, [[_eventsArrayController arrangedObjects] count]);
    [self willChangeValueForKey:@"numberOfFsChanges"];
    [_eventsArrayController removeObjectsAtArrangedObjectIndexes:[NSIndexSet indexSetWithIndexesInRange:indexRange]];
    [self didChangeValueForKey:@"numberOfFsChanges"];
}

- (IBAction)filesInSelectedFolder:(id)sender
{
    if ( ! [self scanFinished] )
    {
        NSAlert* alert = [NSAlert alertWithMessageText:@"Scan is in progress." defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"We cannot show data until we finish scanning!"];
        
        [alert runModal];

        return;
    }
    // stop watching
    [self startWatchingStream:false];
    
    // clear existing events
    [self clearEvents:sender];
    
    [_progressFiles startAnimation:nil];
    
    if ( [arrDFS count] < 15000 )
    {
        [self willChangeValueForKey:@"numberOfFsChanges"];
        [_eventsArrayController addObjects:arrDFS];
        [self didChangeValueForKey:@"numberOfFsChanges"];
    }
    else
    {
        NSAlert* alert = [NSAlert alertWithMessageText:@"Too much data to show! will show first 15,000 rows" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Result set is more than 15,000 rows, not ideal to show here!"];
        
        [alert runModal];
        
        NSRange indexRange = NSMakeRange(0, 15000);
        NSIndexSet *indexSet = [NSIndexSet indexSetWithIndexesInRange:indexRange];
        [self willChangeValueForKey:@"numberOfFsChanges"];
        [_eventsArrayController addObjects:[arrDFS objectsAtIndexes:indexSet]];
        [self didChangeValueForKey:@"numberOfFsChanges"];
    }
    [_progressFiles stopAnimation:nil];
    [_eventsArrayController setSelectionIndex:0];
}

- (IBAction)stopScanningForFiles:(id)sender
{
    if ( ! [self scanFinished] )
    {
        [self setShouldScan:false];
        while (! [self scanFinished])
        {
            NSLog(@"Waiting to finish.");
            [NSThread sleepForTimeInterval:1];
        }
        NSLog(@"We stopped scanning!");
        [self setShouldScan:true];
    }
}

- (void) performFileScanInBackground: (NSString*) rootPath
{
//    // check if already scanning
//    if ( ! [self scanFinished] )
//    {
//        [self setShouldScan:false];
//        while (! [self scanFinished])
//        {
//            NSLog(@"Waiting to finish.");
//            [NSThread sleepForTimeInterval:1];
//        }
//        [self setShouldScan:true];
//    }

    [self stopScanningForFiles:nil];
    
    [_progressBar startAnimation:nil];
    
    @try
    {
        [self setScanFinished: false];
        [_btnStop setEnabled:true];
 
        NSDirectoryEnumerator* dirEnum = [fileManager enumeratorAtPath:rootPath];
        
        NSString* dirObj = nil;
        [arrDFS removeAllObjects];
        
        while( (dirObj = [dirEnum nextObject]) )
        {
            if ( ! [self shouldScan] )
            {
                NSLog(@"We are required to quit this scan. quitting...");
                break;
            }
            NSString *path = [NSString stringWithFormat:@"%@/%@", rootPath, dirObj];
            NSMutableDictionary *row = [NSMutableDictionary dictionaryWithObjectsAndKeys:path, @"path",
                                        [path lastPathComponent], @"name",
                                        [path pathExtension], @"extension",
                                        [NSNumber numberWithUnsignedInt:0], @"flags",
                                        [NSNumber numberWithLongLong:0], @"eventID",
                                        nil];
            
            [self willChangeValueForKey:@"numberOfFiles"];
            [arrDFS addObject:row];
            [self didChangeValueForKey:@"numberOfFiles"];
        }
    }
    @catch (NSException *exception)
    {
        NSLog(@"%@", [exception description]);
    }
    @finally
    {
        [_progressBar stopAnimation:nil];
        [self setScanFinished:true];
        [_btnStop setEnabled:false];
    }
}

@end
