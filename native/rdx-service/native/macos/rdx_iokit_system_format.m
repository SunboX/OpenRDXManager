// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#import <Foundation/Foundation.h>
#include "rdx_iokit_internal.h"
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Fixed format personalities: neither executable paths nor arbitrary arguments
 * cross the renderer/service boundary. Encryption is configured through stdin. */
static NSString *rdx_format_personality(uint32_t selector) {
    switch (selector) {
        case 1: return @"ExFAT";
        case 3: return @"MS-DOS";
        case 4: return @"MS-DOS FAT12";
        case 5: return @"MS-DOS FAT16";
        case 6: return @"MS-DOS FAT32";
        case 7: return @"HFS+";
        case 8: return @"HFSX";
        case 9: return @"JHFS+";
        case 10: return @"JHFSX";
        case 11: case 13: return @"APFS";
        case 12: case 14: return @"APFSX";
        default: return nil;
    }
}

/* Accepts only whole disks or their numeric slice names, never paths/options. */
static bool rdx_format_disk_name(NSString *name, bool whole) {
    if (![name isKindOfClass:NSString.class] || name.length > 63) return false;
    NSString *pattern = whole ? @"^disk[0-9]+$" : @"^disk[0-9]+s[0-9]+$";
    return [name rangeOfString:pattern options:NSRegularExpressionSearch].location != NSNotFound;
}

/* Child output stays in an unlinked bounded capture, never service stdio. The
 * password uses an anonymous pipe, and is never included in argv or environment. */
static NSData *rdx_format_command(NSArray<NSString *> *arguments, NSData *input, bool *success) {
    *success = false;
    FILE *capture = tmpfile();
    if (capture == NULL) return nil;
    NSFileHandle *output = [[NSFileHandle alloc] initWithFileDescriptor:fileno(capture) closeOnDealloc:NO];
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/sbin/diskutil"];
    task.arguments = arguments;
    task.environment = @{@"PATH": @"/usr/bin:/bin:/usr/sbin:/sbin", @"LC_ALL": @"C"};
    task.standardOutput = output;
    task.standardError = [NSFileHandle fileHandleWithNullDevice];
    NSPipe *pipe = input != nil ? [NSPipe pipe] : nil;
    task.standardInput = pipe ? (id)pipe : (id)[NSFileHandle fileHandleWithNullDevice];
    NSData *data = nil;
    @try {
        if ([task launchAndReturnError:nil]) {
            if (pipe) {
                [pipe.fileHandleForWriting writeData:input];
                [pipe.fileHandleForWriting closeFile];
            }
            const NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 180;
            while (task.running && NSProcessInfo.processInfo.systemUptime < deadline) [NSThread sleepForTimeInterval:0.05];
            if (task.running) {
                [task terminate];
                [NSThread sleepForTimeInterval:0.1];
                if (task.running) kill(task.processIdentifier, SIGKILL);
            }
            [task waitUntilExit];
            struct stat facts = {0};
            if (task.terminationStatus == 0 && fstat(fileno(capture), &facts) == 0 && facts.st_size >= 0 && facts.st_size <= 1024 * 1024) {
                [output seekToFileOffset:0];
                data = [output readDataToEndOfFile];
                *success = true;
            }
        }
    } @catch (NSException *exception) {
        (void)exception;
        if (task.running) { kill(task.processIdentifier, SIGKILL); [task waitUntilExit]; }
    }
    if (pipe) [pipe.fileHandleForWriting closeFile];
    fclose(capture);
    return data;
}

/* Parses only bounded Apple plist dictionaries; native text is never surfaced. */
static NSDictionary *rdx_format_plist(NSArray<NSString *> *arguments) {
    bool success = false;
    NSData *data = rdx_format_command(arguments, nil, &success);
    if (!success || !data) return nil;
    id parsed = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:nil error:nil];
    return [parsed isKindOfClass:NSDictionary.class] ? parsed : nil;
}

/* Finds exactly one user volume belonging to the selected whole disk. APFS
 * synthesized disks must resolve through exactly one physical store; shared
 * containers and extra user volumes are rejected. EFI partitions are ignored. */
static NSString *rdx_format_volume(NSString *whole, uint32_t selector, NSDictionary **apfsVolume) {
    NSDictionary *layout = rdx_format_plist(@[@"list", @"-plist", whole]);
    NSArray *disks = layout[@"AllDisksAndPartitions"];
    if (disks.count != 1 || ![disks[0][@"DeviceIdentifier"] isEqual:whole]) return nil;
    NSArray *partitions = disks[0][@"Partitions"];
    NSMutableArray *userPartitions = [NSMutableArray array];
    for (NSDictionary *partition in partitions) if (![partition[@"Content"] isEqual:@"EFI"]) [userPartitions addObject:partition];
    if (userPartitions.count != 1) return nil;
    NSString *partition = userPartitions[0][@"DeviceIdentifier"];
    if (!rdx_format_disk_name(partition, false) || ![partition hasPrefix:[whole stringByAppendingString:@"s"]]) return nil;
    if (selector < 11) return partition;
    NSDictionary *apfs = rdx_format_plist(@[@"apfs", @"list", @"-plist"]);
    NSString *found = nil;
    for (NSDictionary *container in apfs[@"Containers"]) {
        NSArray *stores = container[@"PhysicalStores"];
        if (stores.count != 1 || ![stores[0][@"DeviceIdentifier"] isEqual:partition]) continue;
        NSArray *volumes = container[@"Volumes"];
        if (found || volumes.count != 1) return nil;
        *apfsVolume = volumes[0];
        found = volumes[0][@"DeviceIdentifier"];
        if (!rdx_format_disk_name(found, false)) return nil;
    }
    return found;
}

/* APFS has a synthesized whole disk. Permit a volume only when Apple's
 * mapping proves exactly one physical store on the retained physical disk. */
bool rdx_apfs_volume_matches(DADiskRef disk, uint64_t expected_whole_id) {
    @autoreleasepool {
        const char *bsd = DADiskGetBSDName(disk);
        if (!bsd) return false;
        NSDictionary *info = rdx_format_plist(@[@"info", @"-plist", [NSString stringWithUTF8String:bsd]]);
        NSArray *stores = info[@"APFSPhysicalStores"];
        if (![info[@"FilesystemType"] isEqual:@"apfs"] || stores.count != 1) return false;
        NSString *store = stores[0][@"APFSPhysicalStore"];
        if (!rdx_format_disk_name(store, false)) return false;
        DASessionRef session = DASessionCreate(kCFAllocatorDefault);
        DADiskRef physical = session ? DADiskCreateFromBSDName(kCFAllocatorDefault, session, store.UTF8String) : NULL;
        DADiskRef whole = physical ? DADiskCopyWholeDisk(physical) : NULL;
        io_service_t media = whole ? DADiskCopyIOMedia(whole) : IO_OBJECT_NULL;
        uint64_t identity = 0;
        bool matches = media != IO_OBJECT_NULL && IORegistryEntryGetRegistryEntryID(media, &identity) == kIOReturnSuccess && identity == expected_whole_id;
        if (media != IO_OBJECT_NULL) IOObjectRelease(media);
        if (whole) CFRelease(whole);
        if (physical) CFRelease(physical);
        if (session) CFRelease(session);
        return matches;
    }
}

/* Proves the selected format, writable mount, and completed encryption. */
static bool rdx_format_readback(NSString *whole, uint32_t selector) {
    NSDictionary *apfsVolume = nil;
    NSString *volume = rdx_format_volume(whole, selector, &apfsVolume);
    if (!volume) return false;
    NSDictionary *info = rdx_format_plist(@[@"info", @"-plist", volume]);
    NSString *name = [info[@"FilesystemName"] lowercaseString];
    NSString *type = [info[@"FilesystemType"] lowercaseString];
    if (![info[@"WritableVolume"] boolValue] || [info[@"MountPoint"] length] == 0 || !name) return false;
    if (selector >= 11) {
        bool sensitive = selector == 12 || selector == 14;
        bool encrypted = selector == 13 || selector == 14;
        return [type isEqual:@"apfs"] && [name containsString:@"case-sensitive"] == sensitive &&
            [info[@"Encryption"] boolValue] == encrypted &&
            (!encrypted || ([apfsVolume[@"Encryption"] boolValue] && ![apfsVolume[@"CryptoMigrationOn"] boolValue]));
    }
    if (selector >= 7) {
        bool sensitive = selector == 8 || selector == 10;
        bool journaled = selector == 9 || selector == 10;
        return [type isEqual:@"hfs"] && [name containsString:@"case-sensitive"] == sensitive && [name containsString:@"journaled"] == journaled;
    }
    if (selector == 1) return [type isEqual:@"exfat"];
    return [type isEqual:@"msdos"] && (selector == 3 || [name containsString:selector == 4 ? @"fat12" : selector == 5 ? @"fat16" : @"fat32"]);
}

/* Current whole-media registry identity must agree before every mutation. A
 * filesystem UUID changes during formatting, so it is not a post-write identity. */
static bool rdx_format_target_matches(rdx_macos_device *device) {
    if (!device || !device->session || !device->whole_disk || device->whole_media == IO_OBJECT_NULL) return false;
    /* Resolve the current BSD name anew: a retained DADisk alone could outlive
     * removal while that name is reassigned to another drive. */
    DADiskRef current = DADiskCreateFromBSDName(kCFAllocatorDefault, device->session, device->whole_bsd_name);
    io_service_t media = current ? DADiskCopyIOMedia(current) : IO_OBJECT_NULL;
    uint64_t identity = 0;
    bool exact = media != IO_OBJECT_NULL && IOObjectIsEqualTo(media, device->whole_media) &&
        IORegistryEntryGetRegistryEntryID(media, &identity) == kIOReturnSuccess && identity == device->whole_registry_entry_id &&
        (device->whole_raw_fd < 0 || rdx_raw_fd_matches_disk(device->whole_raw_fd, current));
    if (media != IO_OBJECT_NULL) IOObjectRelease(media);
    if (current) CFRelease(current);
    return exact;
}

/* Formats only a prevalidated exact target. The callback rechecks identity
 * before encryption and terminal readback; test images use their own validator. */
static bool rdx_format_target(NSString *whole, uint32_t selector, const uint8_t *password, size_t length, bool (^validate)(void), bool *attempted) {
    NSString *personality = rdx_format_personality(selector);
    bool encrypted = selector == 13 || selector == 14;
    if (!personality || !rdx_format_disk_name(whole, true) || encrypted != (length > 0) || length > 512 || (length && !password) || !validate()) return false;
    for (size_t index = 0; index < length; ++index) if (password[index] == 0 || password[index] == '\n' || password[index] == '\r') return false;
    NSDictionary *facts = rdx_format_plist(@[@"info", @"-plist", whole]);
    if (!facts) return false;
    NSString *scheme = selector >= 7 || [facts[@"TotalSize"] unsignedLongLongValue] > 2ULL * 1024 * 1024 * 1024 * 1024 ? @"GPT" : @"MBR";
    *attempted = true;
    bool success = false;
    (void)rdx_format_command(@[@"eraseDisk", personality, @"RDX", scheme, whole], nil, &success);
    if (!success || !validate()) {
#if defined(RDX_MACOS_TEST_HOOKS)
        fprintf(stderr, "native-format-test: %s\n", success ? "identity-after-erase" : "erase-tool-failed");
#endif
        return false;
    }
    if (encrypted) {
        NSDictionary *apfsVolume = nil;
        NSString *volume = rdx_format_volume(whole, selector, &apfsVolume);
        if (!volume || !validate()) return false;
        NSMutableData *input = [NSMutableData dataWithBytes:password length:length];
        const uint8_t newline = '\n';
        [input appendBytes:&newline length:1];
        (void)rdx_format_command(@[@"apfs", @"encryptVolume", volume, @"-user", @"disk", @"-stdinpassphrase"], input, &success);
        [input resetBytesInRange:NSMakeRange(0, input.length)];
        if (!success) return false;
    }
    const NSTimeInterval deadline = NSProcessInfo.processInfo.systemUptime + 60;
    do {
        if (!validate()) return false;
        NSDictionary *current = rdx_format_plist(@[@"info", @"-plist", whole]);
        if (![current[@"TotalSize"] isEqual:facts[@"TotalSize"]]) return false;
        if (rdx_format_readback(whole, selector)) return true;
        [NSThread sleepForTimeInterval:0.2];
    } while (NSProcessInfo.processInfo.systemUptime < deadline);
    return false;
}

/* Native entrypoint: retains the RDX authority and rejects stale, mounted,
 * non-writable, internal, and ambiguous targets before dispatch. */
rdx_macos_status rdx_macos_system_format(rdx_macos_device *device, uint32_t selector,
    const uint8_t *password, size_t password_length, rdx_macos_host_operation_result **out_result) {
    if (!out_result) return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    *out_result = NULL;
    rdx_macos_host_operation_result *result = rdx_allocate_result(sizeof(*result), RDX_MACOS_RESULT_HOST_OPERATION);
    if (!result) return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    @autoreleasepool {
        rdx_macos_status status = rdx_revalidate_mapping(device);
        if (status == RDX_MACOS_STATUS_OK && device->whole_raw_fd >= 0 && !rdx_mapping_has_mounted_media(device) && rdx_format_target_matches(device)) {
            NSString *whole = [NSString stringWithUTF8String:device->whole_bsd_name];
            NSDictionary *facts = rdx_format_plist(@[@"info", @"-plist", whole]);
            if ([facts[@"WholeDisk"] boolValue] && ![facts[@"Internal"] boolValue] && [facts[@"WritableMedia"] boolValue] && [facts[@"TotalSize"] unsignedLongLongValue] == device->whole_capacity_bytes) {
                /* Hand the claim to Apple's storage manager immediately before
                 * dispatch while retaining and revalidating the IOMedia owner. */
                if (device->whole_claimed) { DADiskUnclaim(device->whole_disk); device->whole_claimed = false; }
                /* Apple must open the whole disk exclusively. Keep its IOMedia
                 * identity, but release our verified raw fd at this handoff. */
                close(device->whole_raw_fd);
                device->whole_raw_fd = -1;
                bool attempted = false;
                bool complete = rdx_format_target(whole, selector, password, password_length, ^bool{ return rdx_format_target_matches(device); }, &attempted);
                result->attempted = attempted ? 1 : 0;
                result->completed = complete ? 1 : 0;
                status = complete ? RDX_MACOS_STATUS_OK : RDX_MACOS_STATUS_NATIVE_FAILURE;
                rdx_clear_mapping(device);
            } else status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        } else if (status == RDX_MACOS_STATUS_OK) status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        result->header.status = status;
        *out_result = result;
        return status;
    }
}

#if defined(RDX_MACOS_TEST_HOOKS)
/* Explicitly test-only: only tiny virtual disk images, never physical disks. */
bool rdx_macos_test_system_format(const char *bsd, uint32_t selector, const uint8_t *password, size_t length) {
    @autoreleasepool {
        NSString *whole = [NSString stringWithUTF8String:bsd];
        if (!rdx_format_disk_name(whole, true)) return false;
        NSDictionary *initial = rdx_format_plist(@[@"info", @"-plist", whole]);
        if (![initial[@"BusProtocol"] isEqual:@"Disk Image"] || ![initial[@"WholeDisk"] boolValue] || [initial[@"TotalSize"] unsignedLongLongValue] > 1024ULL * 1024 * 1024) return false;
        rdx_macos_device *authority = calloc(1, sizeof(*authority));
        if (!authority) return false;
        authority->session = DASessionCreate(kCFAllocatorDefault);
        authority->whole_disk = authority->session ? DADiskCreateFromBSDName(kCFAllocatorDefault, authority->session, bsd) : NULL;
        authority->whole_media = authority->whole_disk ? DADiskCopyIOMedia(authority->whole_disk) : IO_OBJECT_NULL;
        strlcpy(authority->whole_bsd_name, bsd, sizeof(authority->whole_bsd_name));
        authority->whole_raw_fd = open([[@"/dev/r" stringByAppendingString:whole] fileSystemRepresentation], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (authority->whole_media != IO_OBJECT_NULL) IORegistryEntryGetRegistryEntryID(authority->whole_media, &authority->whole_registry_entry_id);
        bool (^validate)(void) = ^bool{
            NSDictionary *facts = rdx_format_plist(@[@"info", @"-plist", whole]);
            return rdx_format_target_matches(authority) && [facts[@"BusProtocol"] isEqual:@"Disk Image"] && [facts[@"WholeDisk"] boolValue] && [facts[@"TotalSize"] isEqual:initial[@"TotalSize"]];
        };
        bool initially_valid = validate();
        if (authority->whole_raw_fd >= 0) close(authority->whole_raw_fd);
        authority->whole_raw_fd = -1;
        bool attempted = false;
        bool complete = initially_valid && rdx_format_target(whole, selector, password, length, validate, &attempted);
        fprintf(stderr, "native-format-test: attempted=%d complete=%d\n", attempted, complete);
        if (authority->whole_raw_fd >= 0) close(authority->whole_raw_fd);
        if (authority->whole_media != IO_OBJECT_NULL) IOObjectRelease(authority->whole_media);
        if (authority->whole_disk) CFRelease(authority->whole_disk);
        if (authority->session) CFRelease(authority->session);
        free(authority);
        if (!complete || !rdx_macos_test_whole_disk_mapping(bsd)) return false;
        if (selector >= 11) {
            NSDictionary *apfsVolume = nil;
            NSString *volumeName = rdx_format_volume(whole, selector, &apfsVolume);
            DASessionRef session = DASessionCreate(kCFAllocatorDefault);
            DADiskRef physical = DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsd);
            DADiskRef volume = DADiskCreateFromBSDName(kCFAllocatorDefault, session, volumeName.UTF8String);
            io_service_t media = DADiskCopyIOMedia(physical);
            uint64_t identity = 0;
            complete = media != IO_OBJECT_NULL && IORegistryEntryGetRegistryEntryID(media, &identity) == kIOReturnSuccess &&
                rdx_apfs_volume_matches(volume, identity) && !rdx_apfs_volume_matches(volume, identity + 1);
            if (media != IO_OBJECT_NULL) IOObjectRelease(media);
            if (volume) CFRelease(volume);
            if (physical) CFRelease(physical);
            if (session) CFRelease(session);
        }
        return complete;
    }
}
#endif
