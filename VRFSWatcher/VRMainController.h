//
//  VRMainController.h
//  VRFSWatcher
//
//  Created by Viral on 3/25/13.
//  Copyright (c) 2013 Symantec. All rights reserved.
//

#import <Foundation/Foundation.h>

static void fsevents_callback(ConstFSEventStreamRef streamRef,
                              void *userData,
                              size_t numEvents,
                              void *eventPaths,
                              const FSEventStreamEventFlags eventFlags[],
                              const FSEventStreamEventId eventIds[]);



@interface VRMainController : NSObject
{
    // Objects
    NSFileManager* fileManager;
    NSDate* appStartedTimestamp;
    NSNumber* lastEventId;
    FSEventStreamRef stream;

    // data to be represented 
    NSMutableArray *arrDFS;
    
    // controls
    NSTableView *_table;
    __weak NSArrayController *_eventsArrayController;
    __weak NSPredicateEditor *_predicateEditor;
    __weak NSButtonCell *_applyButton;
    __weak NSButton *_resetFilterOnIncomingEvent;
    __weak NSPathControl *_pathToWatch;
    __weak NSButton *_btnWatch;
    __weak NSButton *_btnStop;
    __weak NSProgressIndicator *_progressBar;
    __weak NSProgressIndicator *_progressFiles;
    
    // utility
    Boolean shouldScan;
    Boolean scanFinished;
}

// Properties
@property (assign) IBOutlet NSWindow *window;
@property  IBOutlet NSTableView *table;
@property (readonly) NSNumber *numberOfFsChanges;
@property (readonly) NSNumber *numberOfFiles;

- (IBAction)applyPredicate:(id)sender;
- (IBAction)resetEvents:(id)sender;

@property (weak) IBOutlet NSArrayController *eventsArrayController;
@property (weak) IBOutlet NSPredicateEditor *predicateEditor;
@property (weak) IBOutlet NSButtonCell *applyButton;
@property (weak) IBOutlet NSButton *resetFilterOnIncomingEvent;
@property (weak) IBOutlet NSPathControl *pathToWatch;
@property (weak) IBOutlet NSButton *btnWatch;
@property (weak) IBOutlet NSButton *btnStop;
@property (weak) IBOutlet NSProgressIndicator *progressFiles;

// start / stop
- (IBAction)toggleWatch:(id)sender;
- (IBAction)changePathToWatch:(id)sender;
- (IBAction)stopScanningForFiles:(id)sender;

- (Boolean) shouldScan;
- (void) setShouldScan:(Boolean) setScan;

- (Boolean) scanFinished;
- (void) setScanFinished:(Boolean) setScan;

/// methods

- (void) awakeFromNib;

- (void) registerDefaults;

- (void) initializeEventStream;

- (void) uninitializeEventStream;

- (void) processPath: (NSString*) path withFlags:(FSEventStreamEventFlags) flag andEventID:(FSEventStreamEventId)eventId;

- (void)updateLastEventId: (uint64_t) eventId;

- (NSApplicationTerminateReply)applicationShouldTerminate: (NSApplication *)app;

- (IBAction)clearEvents:(id)sender;

- (IBAction)filesInSelectedFolder:(id)sender;

@property (weak) IBOutlet NSProgressIndicator *progressBar;

@end


void fsevents_callback(ConstFSEventStreamRef streamRef,
                       void *userData,
                       size_t numEvents,
                       void *eventPaths,
                       const FSEventStreamEventFlags eventFlags[],
                       const FSEventStreamEventId eventIds[])
{
    VRMainController *ac = (__bridge VRMainController *) userData;
    
    size_t i;
    for(i=0; i < numEvents; i++){
        [ac processPath: [(__bridge NSArray *)eventPaths objectAtIndex:i] withFlags:eventFlags[i] andEventID:eventIds[i]];
    }
}
