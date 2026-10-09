//  Copyright (C) 2015-2019 Pierre-Olivier Latour <info@pol-online.net>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#if !__has_feature(objc_arc)
#error This file requires ARC
#endif

#import "GCPrivate.h"

#if !TARGET_OS_IPHONE

static NSString* _StringFromTaskOutput(NSData* data) {
  return [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static NSString* _RepositoryTaskDirectoryPath(GCRepository* repository) {
  return repository.workingDirectoryPath ?: repository.repositoryPath;
}

static NSError* _TaskFailureError(NSString* message, int status, NSData* stdoutData, NSData* stderrData) {
  NSString* output = _StringFromTaskOutput(stderrData.length ? stderrData : stdoutData);
  NSString* reason = output.length ? [NSString stringWithFormat:@": %@", output] : @"";
  return GCNewError(kGCErrorCode_Generic, [NSString stringWithFormat:@"%@ exited with non-zero status (%i)%@", message, status, reason]);
}

static GCTask* _TaskWithPATH(GCRepository* repository, NSString* executablePath, NSString* path) {
  GCTask* task = [[GCTask alloc] initWithExecutablePath:executablePath];
  task.currentDirectoryPath = _RepositoryTaskDirectoryPath(repository);
  task.additionalEnvironment = @{@"PATH" : path};
  return task;
}

static BOOL _ReadConfigBool(GCRepository* repository, const char* variable, BOOL* value, NSError** error) {
  BOOL success = NO;
  git_config* config = NULL;
  int configValue = 0;
  int status;

  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_repository_config, &config, repository.private);
  status = git_config_get_bool(&configValue, config, variable);
  if (status == GIT_ENOTFOUND) {
    *value = NO;
    success = YES;
    goto cleanup;
  }
  CHECK_LIBGIT2_FUNCTION_CALL(goto cleanup, status, == GIT_OK);
  *value = configValue ? YES : NO;
  success = YES;

cleanup:
  git_config_free(config);
  return success;
}

typedef NS_ENUM(NSUInteger, GCCommitSigningFormat) {
  kGCCommitSigningFormat_None = 0,
  kGCCommitSigningFormat_OpenPGP,
  kGCCommitSigningFormat_X509,
  kGCCommitSigningFormat_SSH
};

static NSString* _ReadConfigString(GCRepository* repository, NSString* variable) {
  NSString* value = [[repository readConfigOptionForVariable:variable error:NULL] value];
  value = [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
  return value.length ? value : nil;
}

static BOOL _CommitSigningFormat(GCRepository* repository, GCCommitSigningFormat* format, NSError** error) {
  BOOL gpgSign = NO;
  if (!_ReadConfigBool(repository, "commit.gpgsign", &gpgSign, error)) {
    return NO;
  }
  if (!gpgSign) {
    *format = kGCCommitSigningFormat_None;
    return YES;
  }

  // Matches the Git CLI which defaults to OpenPGP and rejects unknown formats
  NSString* value = _ReadConfigString(repository, @"gpg.format");
  if (!value || ([value caseInsensitiveCompare:@"openpgp"] == NSOrderedSame)) {
    *format = kGCCommitSigningFormat_OpenPGP;
  } else if ([value caseInsensitiveCompare:@"x509"] == NSOrderedSame) {
    *format = kGCCommitSigningFormat_X509;
  } else if ([value caseInsensitiveCompare:@"ssh"] == NSOrderedSame) {
    *format = kGCCommitSigningFormat_SSH;
  } else {
    if (error) {
      *error = GCNewError(kGCErrorCode_Generic, [NSString stringWithFormat:@"Unsupported commit signing format \"%@\" in gpg.format", value]);
    }
    return NO;
  }
  return YES;
}

static BOOL _LooksLikeInlineSSHKey(NSString* key) {
  return [key hasPrefix:@"ssh-"] || [key hasPrefix:@"ecdsa-"] || [key hasPrefix:@"sk-"];
}

static NSString* _SSHKeyFromDefaultKeyCommand(GCRepository* repository, NSString* command, NSString* path, NSError** error) {
  GCTask* task = _TaskWithPATH(repository, @"/bin/sh", path);
  int status;
  NSData* stdoutData;
  NSData* stderrData;
  if (![task runWithArguments:@[ @"-c", command ] stdin:nil stdout:&stdoutData stderr:&stderrData exitStatus:&status error:error]) {
    return nil;
  }
  if (status != 0) {
    if (error) {
      *error = _TaskFailureError(@"SSH signing default key command", status, stdoutData, stderrData);
    }
    return nil;
  }

  NSString* output = [[NSString alloc] initWithData:stdoutData encoding:NSUTF8StringEncoding];
  for (NSString* line in [output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
    NSString* trimmedLine = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if ([trimmedLine hasPrefix:@"key::"]) {
      NSString* key = [trimmedLine substringFromIndex:5];
      return key.length ? key : nil;
    }
  }
  if (error) {
    *error = GCNewError(kGCErrorCode_Generic, @"SSH signing default key command did not return a key:: entry");
  }
  return nil;
}

static NSString* _TemporaryKeyFileForInlineSSHKey(NSString* key, NSError** error) {
  NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]];
  NSString* contents = [key hasSuffix:@"\n"] ? key : [key stringByAppendingString:@"\n"];
  if (![contents writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:error]) {
    return nil;
  }
  return path;
}

static NSString* _SSHSigningKeyPath(GCRepository* repository, NSString* taskPath, NSString** temporaryPath, NSError** error) {
  NSString* key = [[repository readConfigOptionForVariable:@"user.signingkey" error:NULL] value];
  if (key.length) {
    key = [key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
  } else {
    NSString* command = [[repository readConfigOptionForVariable:@"gpg.ssh.defaultKeyCommand" error:NULL] value];
    if (!command.length) {
      if (error) {
        *error = GCNewError(kGCErrorCode_Generic, @"SSH commit signing requires user.signingkey or gpg.ssh.defaultKeyCommand");
      }
      return nil;
    }
    key = _SSHKeyFromDefaultKeyCommand(repository, command, taskPath, error);
    if (!key) {
      return nil;
    }
  }

  if ([key hasPrefix:@"key::"]) {
    key = [key substringFromIndex:5];
  }
  if (_LooksLikeInlineSSHKey(key)) {
    NSString* path = _TemporaryKeyFileForInlineSSHKey(key, error);
    if (!path) {
      return nil;
    }
    *temporaryPath = path;
    return path;
  }

  NSString* path = key.stringByExpandingTildeInPath;
  if (!path.absolutePath) {
    NSString* relativePath = [_RepositoryTaskDirectoryPath(repository) stringByAppendingPathComponent:path];
    if ([[NSFileManager defaultManager] fileExistsAtPath:relativePath]) {
      path = relativePath;
    }
  }
  return path;
}

static NSString* _SSHSignatureForCommitBuffer(GCRepository* repository, NSData* commitBuffer, NSString* path, NSError** error) {
  NSString* temporaryKeyPath = nil;
  NSString* keyPath = _SSHSigningKeyPath(repository, path, &temporaryKeyPath, error);
  if (!keyPath) {
    return nil;
  }

  NSString* program = [[repository readConfigOptionForVariable:@"gpg.ssh.program" error:NULL] value];
  program = program.length ? program.stringByExpandingTildeInPath : @"ssh-keygen";

  GCTask* task = _TaskWithPATH(repository, @"/usr/bin/env", path);
  int status;
  NSData* stdoutData;
  NSData* stderrData;
  NSArray* arguments = @[ program, @"-Y", @"sign", @"-n", @"git", @"-f", keyPath ];
  BOOL success = [task runWithArguments:arguments stdin:commitBuffer stdout:&stdoutData stderr:&stderrData exitStatus:&status error:error];
  if (temporaryKeyPath) {
    [[NSFileManager defaultManager] removeItemAtPath:temporaryKeyPath error:NULL];
  }
  if (!success) {
    return nil;
  }
  if (status != 0) {
    if (error) {
      *error = _TaskFailureError(@"SSH commit signer", status, stdoutData, stderrData);
    }
    return nil;
  }

  NSString* signature = _StringFromTaskOutput(stdoutData);
  if (!signature.length) {
    if (error) {
      *error = GCNewError(kGCErrorCode_Generic, @"SSH commit signer did not return a signature");
    }
    return nil;
  }
  return signature;
}

static NSString* _GPGStatusFreeOutput(NSData* stderrData) {
  NSMutableArray* lines = [[NSMutableArray alloc] init];
  for (NSString* line in [_StringFromTaskOutput(stderrData) componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
    if (line.length && ![line hasPrefix:@"[GNUPG:]"]) {
      [lines addObject:line];
    }
  }
  return [lines componentsJoinedByString:@"\n"];
}

// Mirrors sign_buffer_gpg() from the Git CLI which is used for both OpenPGP and X.509 signing
static NSString* _GPGSignatureForCommitBuffer(GCRepository* repository, GCCommitSigningFormat format, const git_signature* committer, NSData* commitBuffer, NSString* path, NSError** error) {
  NSString* program;
  if (format == kGCCommitSigningFormat_X509) {
    program = _ReadConfigString(repository, @"gpg.x509.program") ?: @"gpgsm";
  } else {
    program = _ReadConfigString(repository, @"gpg.openpgp.program");
    if (!program) {
      program = _ReadConfigString(repository, @"gpg.program") ?: @"gpg";
    }
  }
  program = program.stringByExpandingTildeInPath;

  NSString* key = _ReadConfigString(repository, @"user.signingkey");
  if (!key) {
    key = GCUserFromSignature(committer);  // Same default as the Git CLI i.e. the committer identity
  }

  GCTask* task = _TaskWithPATH(repository, @"/usr/bin/env", path);
  int status;
  NSData* stdoutData;
  NSData* stderrData;
  NSArray* arguments = @[ program, @"--status-fd=2", @"-bsau", key ];
  if (![task runWithArguments:arguments stdin:commitBuffer stdout:&stdoutData stderr:&stderrData exitStatus:&status error:error]) {
    return nil;
  }

  NSString* statusOutput = [@"\n" stringByAppendingString:([[NSString alloc] initWithData:stderrData encoding:NSUTF8StringEncoding] ?: @"")];
  NSString* signature = _StringFromTaskOutput(stdoutData);
  if ((status != 0) || ![statusOutput containsString:@"\n[GNUPG:] SIG_CREATED "] || !signature.length) {
    if (error) {
      NSString* output = _GPGStatusFreeOutput(stderrData);
      NSString* message = [NSString stringWithFormat:@"%@ commit signer failed to sign the data with key \"%@\"", format == kGCCommitSigningFormat_X509 ? @"X.509" : @"GPG", key];
      if (status != 0) {
        message = [message stringByAppendingFormat:@" (exit status %i)", status];
      }
      if (output.length) {
        message = [message stringByAppendingFormat:@": %@", output];
      }
      if ([output rangeOfString:@"pinentry" options:NSCaseInsensitiveSearch].location != NSNotFound || [output containsString:@"Inappropriate ioctl for device"]) {
        message = [message stringByAppendingString:@" (GitUp cannot prompt for a passphrase in a terminal so gpg-agent must be configured with a graphical pinentry program like pinentry-mac)"];
      }
      *error = GCNewError(kGCErrorCode_Generic, message);
    }
    return nil;
  }
  return signature;
}

static NSString* _SignatureForCommitBuffer(GCRepository* repository, GCCommitSigningFormat format, const git_signature* committer, NSData* commitBuffer, NSError** error) {
  NSString* path = [repository commitSigningPATH:error];
  if (!path) {
    return nil;
  }
  if (format == kGCCommitSigningFormat_SSH) {
    return _SSHSignatureForCommitBuffer(repository, commitBuffer, path, error);
  }
  return _GPGSignatureForCommitBuffer(repository, format, committer, commitBuffer, path, error);
}

#endif

GCCommit* GCCreateCommitWithOptionalSignature(GCRepository* repository, git_tree* tree, const git_commit** parents, NSUInteger count, const git_signature* author, const git_signature* committer, const char* messageEncoding, const char* message, NSError** error) {
  GCCommit* commit = nil;
  git_commit* newCommit = NULL;
#if !TARGET_OS_IPHONE
  git_buf commitBuffer = {0};
  NSData* commitData = nil;
  NSString* signature = nil;
  GCCommitSigningFormat format = kGCCommitSigningFormat_None;
#endif

  git_oid oid;
#if !TARGET_OS_IPHONE
  if (!_CommitSigningFormat(repository, &format, error)) {
    goto cleanup;
  }

  if (format != kGCCommitSigningFormat_None) {
    CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_create_buffer, &commitBuffer, repository.private, author, committer, messageEncoding, message, tree, count, parents);
    commitData = [[NSData alloc] initWithBytes:commitBuffer.ptr length:commitBuffer.size];
    signature = _SignatureForCommitBuffer(repository, format, committer, commitData, error);
    if (!signature) {
      goto cleanup;
    }
    CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_create_with_signature, &oid, repository.private, commitBuffer.ptr, signature.UTF8String, "gpgsig");
  } else {
#endif
    CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_create, &oid, repository.private, NULL, author, committer, messageEncoding, message, tree, count, parents);
#if !TARGET_OS_IPHONE
  }
#endif
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_lookup, &newCommit, repository.private, &oid);
  commit = [[GCCommit alloc] initWithRepository:repository commit:newCommit];
  newCommit = NULL;

cleanup:
  git_commit_free(newCommit);
#if !TARGET_OS_IPHONE
  git_buf_free(&commitBuffer);
#endif
  return commit;
}

GCCommit* GCCreateCommitFromTreeWithOptionalSignature(GCRepository* repository, git_tree* tree, const git_commit** parents, NSUInteger count, const git_signature* author, NSString* message, NSError** error) {
  GCCommit* commit = nil;
  git_signature* signature = NULL;
  NSData* cleanedMessage = GCCleanedUpCommitMessage(message);

  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_signature_default, &signature, repository.private);
  commit = GCCreateCommitWithOptionalSignature(repository, tree, parents, count, author ?: signature, signature, NULL, (const char*)cleanedMessage.bytes, error);

cleanup:
  git_signature_free(signature);
  return commit;
}

GCCommit* GCCreateCommitFromCommitWithIndexAndOptionalSignature(GCRepository* repository, git_commit* amendedCommit, git_index* index, NSString* message, NSError** error) {
  GCCommit* commit = nil;
  git_tree* tree = NULL;
  git_commit** parentCommits = NULL;
  unsigned int parentCount = 0;
  const git_commit** parents = NULL;

  git_oid oid;
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_index_write_tree_to, &oid, index, repository.private);
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_tree_lookup, &tree, repository.private, &oid);

  parentCount = git_commit_parentcount(amendedCommit);
  if (parentCount) {
    parentCommits = (git_commit**)calloc(parentCount, sizeof(git_commit*));
    if (!parentCommits) {
      GC_SET_GENERIC_ERROR(@"Unable to allocate commit parent list");
      goto cleanup;
    }
    for (unsigned int i = 0; i < parentCount; ++i) {
      CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_parent, &parentCommits[i], amendedCommit, i);
    }
  }
  parents = (const git_commit**)parentCommits;

  commit = GCCreateCommitFromTreeWithOptionalSignature(repository, tree, parents, parentCount, git_commit_author(amendedCommit), message, error);

cleanup:
  if (parentCommits) {
    for (unsigned int i = 0; i < parentCount; ++i) {
      git_commit_free(parentCommits[i]);
    }
    free(parentCommits);
  }
  git_tree_free(tree);
  return commit;
}
