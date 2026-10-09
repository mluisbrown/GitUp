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

#import "GCTestCase.h"
#import "GCCommitSigningTestHelpers.h"
#import "GCRepository+Index.h"
#import "GCRepository+Bare.h"

static BOOL _WriteLocalConfigOption(GCRepository* repository, NSString* variable, NSString* value) {
  return [repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:variable withValue:value error:NULL];
}

static BOOL _WriteExecutable(NSString* path, NSString* contents) {
  if (![contents writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL]) {
    return NO;
  }
  return [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions : @(0755)} ofItemAtPath:path error:NULL];
}

static NSString* _CreateFakeSSHSigner(NSString* directory, int exitStatus) {
  NSString* path = [directory stringByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]];
  NSString* contents;

  if (exitStatus == 0) {
    NSArray* lines = @[
      @"#!/bin/sh",
      @"cat >/dev/null",
      @"printf '%s\\n' '-----BEGIN SSH SIGNATURE-----' 'fake-signature' '-----END SSH SIGNATURE-----'",
      @""
    ];
    contents = [lines componentsJoinedByString:@"\n"];
  } else {
    NSArray* lines = @[
      @"#!/bin/sh",
      @"cat >/dev/null",
      @"echo signer failed >&2",
      [NSString stringWithFormat:@"exit %i", exitStatus],
      @""
    ];
    contents = [lines componentsJoinedByString:@"\n"];
  }

  return _WriteExecutable(path, contents) ? path : nil;
}

// Behaves like "gpg --status-fd=2 -bsau <key>" and records the requested key
static NSString* _CreateFakeGPGSigner(NSString* directory, NSString* keyOutputPath, BOOL reportSignature) {
  NSString* path = [directory stringByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]];
  NSArray* lines = @[
    @"#!/bin/sh",
    @"[ \"$1\" = \"--status-fd=2\" ] && [ \"$2\" = \"-bsau\" ] || exit 2",
    [NSString stringWithFormat:@"printf '%%s' \"$3\" > '%@'", keyOutputPath],
    @"cat >/dev/null",
    @"echo '[GNUPG:] KEY_CONSIDERED 0000000000000000000000000000000000000000 0' >&2",
    reportSignature ? @"echo '[GNUPG:] SIG_CREATED D 1 8 00 1700000000 0000000000000000000000000000000000000000' >&2" : @"echo 'gpg: signing failed: Inappropriate ioctl for device' >&2",
    @"printf '%s\\n' '-----BEGIN PGP SIGNATURE-----' '' 'fake-signature' '-----END PGP SIGNATURE-----'",
    @""
  ];
  return _WriteExecutable(path, [lines componentsJoinedByString:@"\n"]) ? path : nil;
}

static GCCommit* _CreateCommitFromRepositoryIndex(GCRepository* repository, NSString* message, NSError** error) {
  GCCommit* commit = nil;
  git_index* index = NULL;
  git_tree* tree = NULL;

  index = [repository reloadRepositoryIndex:error];
  if (!index) {
    goto cleanup;
  }

  git_oid oid;
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_index_write_tree_to, &oid, index, repository.private);
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_tree_lookup, &tree, repository.private, &oid);
  commit = GCCreateCommitFromTreeWithOptionalSignature(repository,
                                                       tree,
                                                       NULL,
                                                       0,
                                                       NULL,
                                                       message,
                                                       error);

cleanup:
  git_tree_free(tree);
  git_index_free(index);
  return commit;
}

@implementation GCEmptyRepositoryTests (GCCommitSigning)

- (void)testCommitSigningLeavesCommitsUnsignedWhenDisabled {
  [self updateFileAtPath:@"unsigned.txt" withString:@"unsigned\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"unsigned.txt" error:NULL]);

  GCCommit* unsignedCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Unsigned", NULL);
  XCTAssertNotNil(unsignedCommit);
  XCTAssertNil(GCCommitSignature(unsignedCommit));

  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"false"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"ssh"));
  [self updateFileAtPath:@"disabled.txt" withString:@"disabled\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"disabled.txt" error:NULL]);

  GCCommit* disabledCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Signing disabled", NULL);
  XCTAssertNotNil(disabledCommit);
  XCTAssertNil(GCCommitSignature(disabledCommit));
}

- (void)testCommitSigningRejectsUnknownFormat {
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"bogus"));
  [self updateFileAtPath:@"unknown-format.txt" withString:@"unknown format\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"unknown-format.txt" error:NULL]);

  NSError* error;
  XCTAssertNil(_CreateCommitFromRepositoryIndex(self.repository, @"Unknown format", &error));
  XCTAssertTrue([error.localizedDescription containsString:@"gpg.format"]);
}

- (void)testCommitSigningSupportsOpenPGP {
  NSString* keyOutput = [self.temporaryPath stringByAppendingPathComponent:@"gpg-key"];
  NSString* signer = _CreateFakeGPGSigner(self.temporaryPath, keyOutput, YES);
  XCTAssertNotNil(signer);
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.program", signer));

  // Without user.signingkey the committer identity is used like the Git CLI does
  [self updateFileAtPath:@"default-gpg-key.txt" withString:@"default key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"default-gpg-key.txt" error:NULL]);
  GCCommit* defaultKeyCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Default GPG key", NULL);
  XCTAssertNotNil(defaultKeyCommit);
  XCTAssertTrue(GCCommitHasPGPSignature(defaultKeyCommit));
  XCTAssertEqualObjects([NSString stringWithContentsOfFile:keyOutput encoding:NSUTF8StringEncoding error:NULL], defaultKeyCommit.committer);

  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"openpgp"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"user.signingkey", @"ABCDEF0123456789"));
  [self updateFileAtPath:@"explicit-gpg-key.txt" withString:@"explicit key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"explicit-gpg-key.txt" error:NULL]);
  GCCommit* explicitKeyCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Explicit GPG key", NULL);
  XCTAssertNotNil(explicitKeyCommit);
  XCTAssertTrue(GCCommitHasPGPSignature(explicitKeyCommit));
  XCTAssertEqualObjects([NSString stringWithContentsOfFile:keyOutput encoding:NSUTF8StringEncoding error:NULL], @"ABCDEF0123456789");
}

- (void)testCommitSigningSupportsX509 {
  NSString* keyOutput = [self.temporaryPath stringByAppendingPathComponent:@"x509-key"];
  NSString* signer = _CreateFakeGPGSigner(self.temporaryPath, keyOutput, YES);
  XCTAssertNotNil(signer);
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"x509"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.x509.program", signer));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"user.signingkey", @"0x12345678"));
  [self updateFileAtPath:@"x509.txt" withString:@"x509\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"x509.txt" error:NULL]);

  GCCommit* commit = _CreateCommitFromRepositoryIndex(self.repository, @"X.509", NULL);
  XCTAssertNotNil(commit);
  XCTAssertNotNil(GCCommitSignature(commit));
  XCTAssertEqualObjects([NSString stringWithContentsOfFile:keyOutput encoding:NSUTF8StringEncoding error:NULL], @"0x12345678");
}

- (void)testCommitSigningFailsWithoutGPGSignatureStatus {
  NSString* keyOutput = [self.temporaryPath stringByAppendingPathComponent:@"gpg-key"];
  NSString* signer = _CreateFakeGPGSigner(self.temporaryPath, keyOutput, NO);
  XCTAssertNotNil(signer);
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.program", signer));
  [self updateFileAtPath:@"gpg-failure.txt" withString:@"gpg failure\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"gpg-failure.txt" error:NULL]);

  NSError* error;
  XCTAssertNil(_CreateCommitFromRepositoryIndex(self.repository, @"GPG failure", &error));
  XCTAssertTrue([error.localizedDescription containsString:@"failed to sign"]);
  XCTAssertTrue([error.localizedDescription containsString:@"pinentry"]);
  XCTAssertFalse([error.localizedDescription containsString:@"[GNUPG:]"]);
}

- (void)testCommitSigningSignsRewrittenCommits {
  GCCommit* commit1 = [self makeCommitWithUpdatedFileAtPath:@"rewrite.txt" string:@"1\n" message:@"1"];
  GCCommit* commit2 = [self makeCommitWithUpdatedFileAtPath:@"rewrite.txt" string:@"2\n" message:@"2"];
  GCCommit* commit3 = [self makeCommitWithUpdatedFileAtPath:@"other.txt" string:@"3\n" message:@"3"];
  XCTAssertNil(GCCommitSignature(commit2));

  NSString* signer = _CreateFakeSSHSigner(self.temporaryPath, 0);
  XCTAssertNotNil(signer);
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"ssh"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.ssh.program", signer));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"user.signingkey", @"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRewriteKey test@example.com"));

  // Reword keeps the original parents
  GCCommit* reworded = [self.repository copyCommit:commit2 withUpdatedMessage:@"2 reworded" updatedParents:nil updatedTreeFromIndex:nil updateCommitter:YES error:NULL];
  XCTAssertNotNil(reworded);
  XCTAssertTrue(GCCommitHasSSHSignature(reworded));
  XCTAssertEqualObjects([self.repository lookupParentsForCommit:reworded error:NULL], @[ commit1 ]);
  XCTAssertEqualObjects(reworded.message, @"2 reworded");

  // Replay onto new parents
  GCCommit* replayed = [self.repository replayCommit:commit3
                                          ontoCommit:reworded
                                  withAncestorCommit:commit2
                                      updatedMessage:nil
                                      updatedParents:@[ reworded ]
                                     updateCommitter:YES
                                       skipIdentical:NO
                                     conflictHandler:NULL
                                               error:NULL];
  XCTAssertNotNil(replayed);
  XCTAssertTrue(GCCommitHasSSHSignature(replayed));
  XCTAssertEqualObjects([self.repository lookupParentsForCommit:replayed error:NULL], @[ reworded ]);
  XCTAssertEqualObjects(replayed.message, commit3.message);

  // Squash
  GCCommit* squashed = [self.repository squashCommitOntoParent:commit2 withUpdatedMessage:@"Squashed" error:NULL];
  XCTAssertNotNil(squashed);
  XCTAssertTrue(GCCommitHasSSHSignature(squashed));

  // Cherry-pick goes through the merge code path
  GCCommit* picked = [self.repository cherryPickCommit:commit3 againstCommit:commit1 withAncestorCommit:commit2 message:@"Picked" conflictHandler:NULL error:NULL];
  XCTAssertNotNil(picked);
  XCTAssertTrue(GCCommitHasSSHSignature(picked));
}

- (void)testCommitSigningSessionReusesPATH {
  NSString* pathLookups = [self.temporaryPath stringByAppendingPathComponent:@"session-path-lookups"];
  NSString* shell = [self.temporaryPath stringByAppendingPathComponent:@"session-path-shell"];
  NSString* shellContents = [NSString stringWithFormat:@"#!/bin/sh\nprintf x >> '%@'\necho \"$PATH\"\n", pathLookups];
  XCTAssertTrue(_WriteExecutable(shell, shellContents));

  NSString* signer = _CreateFakeSSHSigner(self.temporaryPath, 0);
  XCTAssertNotNil(signer);
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"ssh"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.ssh.program", signer));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"user.signingkey", @"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISessionKey test@example.com"));

  const char* previousShellValue = getenv("SHELL");
  NSString* previousShell = previousShellValue ? [NSString stringWithUTF8String:previousShellValue] : nil;
  setenv("SHELL", shell.fileSystemRepresentation, 1);
  @try {
    [self.repository beginCommitSigningSession];
    for (NSString* name in @[ @"session-1.txt", @"session-2.txt" ]) {
      [self updateFileAtPath:name withString:name];
      XCTAssertTrue([self.repository addFileToIndex:name error:NULL]);
      GCCommit* commit = _CreateCommitFromRepositoryIndex(self.repository, name, NULL);
      XCTAssertTrue(GCCommitHasSSHSignature(commit));
    }
    [self.repository endCommitSigningSession];
    XCTAssertEqual([[NSString stringWithContentsOfFile:pathLookups encoding:NSUTF8StringEncoding error:NULL] length], 1);

    [self updateFileAtPath:@"session-3.txt" withString:@"3"];
    XCTAssertTrue([self.repository addFileToIndex:@"session-3.txt" error:NULL]);
    XCTAssertTrue(GCCommitHasSSHSignature(_CreateCommitFromRepositoryIndex(self.repository, @"After session", NULL)));
    XCTAssertEqual([[NSString stringWithContentsOfFile:pathLookups encoding:NSUTF8StringEncoding error:NULL] length], 2);
  } @finally {
    if (previousShell) {
      setenv("SHELL", previousShell.fileSystemRepresentation, 1);
    } else {
      unsetenv("SHELL");
    }
  }
}

- (void)testCommitSigningRequiresSSHKey {
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"ssh"));
  [self updateFileAtPath:@"missing-key.txt" withString:@"missing key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"missing-key.txt" error:NULL]);

  NSError* error;
  XCTAssertNil(_CreateCommitFromRepositoryIndex(self.repository, @"Missing key", &error));
  XCTAssertTrue([error.localizedDescription containsString:@"user.signingkey"]);
}

- (void)testCommitSigningRefreshesPATHOncePerOperation {
  NSString* firstDirectory = [self.temporaryPath stringByAppendingPathComponent:@"first"];
  NSString* secondDirectory = [self.temporaryPath stringByAppendingPathComponent:@"second"];
  NSString* pathOutput = [self.temporaryPath stringByAppendingPathComponent:@"signing-path"];
  NSString* pathLookups = [self.temporaryPath stringByAppendingPathComponent:@"path-lookups"];
  NSString* shell = [self.temporaryPath stringByAppendingPathComponent:@"path-shell"];
  NSString* program = @"test-ssh-signer";
  NSString* defaultKeyCommand = @"test-default-key";

  XCTAssertTrue([[NSFileManager defaultManager] createDirectoryAtPath:firstDirectory withIntermediateDirectories:NO attributes:nil error:NULL]);
  XCTAssertTrue([[NSFileManager defaultManager] createDirectoryAtPath:secondDirectory withIntermediateDirectories:NO attributes:nil error:NULL]);

  NSString* shellContents = [NSString stringWithFormat:@"#!/bin/sh\nprintf x >> '%@'\n/bin/cat '%@'\n", pathLookups, pathOutput];
  XCTAssertTrue(_WriteExecutable(shell, shellContents));

  for (NSString* directory in @[ firstDirectory, secondDirectory ]) {
    NSString* marker = [directory isEqualToString:firstDirectory] ? @"first-signature" : @"second-signature";
    NSString* signerContents = [NSString stringWithFormat:@"#!/bin/sh\n/bin/cat >/dev/null\nprintf '%%s\\n' '-----BEGIN SSH SIGNATURE-----' '%@' '-----END SSH SIGNATURE-----'\n", marker];
    XCTAssertTrue(_WriteExecutable([directory stringByAppendingPathComponent:program], signerContents));
    XCTAssertTrue(_WriteExecutable([directory stringByAppendingPathComponent:defaultKeyCommand],
                                   @"#!/bin/sh\nprintf 'key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPathRefreshKey test@example.com\\n'\n"));
  }

  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"ssh"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.ssh.program", program));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.ssh.defaultKeyCommand", defaultKeyCommand));

  const char* previousShellValue = getenv("SHELL");
  NSString* previousShell = previousShellValue ? [NSString stringWithUTF8String:previousShellValue] : nil;
  setenv("SHELL", shell.fileSystemRepresentation, 1);
  @try {
    XCTAssertTrue([[firstDirectory stringByAppendingString:@"\n"] writeToFile:pathOutput atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
    [self updateFileAtPath:@"first-path.txt" withString:@"first path\n"];
    XCTAssertTrue([self.repository addFileToIndex:@"first-path.txt" error:NULL]);
    GCCommit* firstCommit = _CreateCommitFromRepositoryIndex(self.repository, @"First PATH", NULL);
    XCTAssertNotNil(firstCommit);
    XCTAssertTrue([GCCommitSignature(firstCommit) containsString:@"first-signature"]);
    XCTAssertEqual([[NSString stringWithContentsOfFile:pathLookups encoding:NSUTF8StringEncoding error:NULL] length], 1);

    XCTAssertTrue([[secondDirectory stringByAppendingString:@"\n"] writeToFile:pathOutput atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
    [self updateFileAtPath:@"second-path.txt" withString:@"second path\n"];
    XCTAssertTrue([self.repository addFileToIndex:@"second-path.txt" error:NULL]);
    GCCommit* secondCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Second PATH", NULL);
    XCTAssertNotNil(secondCommit);
    XCTAssertTrue([GCCommitSignature(secondCommit) containsString:@"second-signature"]);
    XCTAssertEqual([[NSString stringWithContentsOfFile:pathLookups encoding:NSUTF8StringEncoding error:NULL] length], 2);
  } @finally {
    if (previousShell) {
      setenv("SHELL", previousShell.fileSystemRepresentation, 1);
    } else {
      unsetenv("SHELL");
    }
  }
}

- (void)testCommitSigningSupportsInlineKeyAndDefaultKeyCommand {
  NSString* signer = _CreateFakeSSHSigner(self.temporaryPath, 0);
  NSString* inlineKey = @"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeInlineKey test@example.com";
  NSString* defaultKeyCommand = @"printf 'key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDefaultCommandKey test@example.com\\n'";

  XCTAssertNotNil(signer);
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"ssh"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.ssh.program", signer));

  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"user.signingkey", inlineKey));
  [self updateFileAtPath:@"inline-key.txt" withString:@"inline key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"inline-key.txt" error:NULL]);

  GCCommit* inlineCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Inline key", NULL);
  XCTAssertNotNil(inlineCommit);
  XCTAssertTrue(GCCommitHasSSHSignature(inlineCommit));

  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"user.signingkey", nil));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.ssh.defaultKeyCommand", defaultKeyCommand));
  [self updateFileAtPath:@"default-key-command.txt" withString:@"default key command\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"default-key-command.txt" error:NULL]);

  GCCommit* defaultCommandCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Default key command", NULL);
  XCTAssertNotNil(defaultCommandCommit);
  XCTAssertTrue(GCCommitHasSSHSignature(defaultCommandCommit));
}

- (void)testCommitSigningSupportsKeyPath {
  NSString* keyPath = [self.temporaryPath stringByAppendingPathComponent:@"signing_key"];
  GCTask* keygen = [[GCTask alloc] initWithExecutablePath:@"/usr/bin/ssh-keygen"];
  int status;
  NSArray* keygenArguments = @[ @"-t", @"ed25519", @"-f", keyPath, @"-N", @"", @"-q" ];
  BOOL keygenSuccess = [keygen runWithArguments:keygenArguments stdin:nil stdout:NULL stderr:NULL exitStatus:&status error:NULL];
  XCTAssertTrue(keygenSuccess);
  XCTAssertEqual(status, 0);
  XCTAssertTrue(GCConfigureSSHSigningWithKeyPath(self.repository, keyPath));

  [self updateFileAtPath:@"path-key.txt" withString:@"path key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"path-key.txt" error:NULL]);

  GCCommit* commit = _CreateCommitFromRepositoryIndex(self.repository, @"Path key", NULL);
  XCTAssertNotNil(commit);
  XCTAssertTrue(GCCommitHasSSHSignature(commit));

  NSString* publicKey = [NSString stringWithContentsOfFile:[keyPath stringByAppendingString:@".pub"] encoding:NSUTF8StringEncoding error:NULL];
  NSString* allowedSignersPath = [self.temporaryPath stringByAppendingPathComponent:@"allowed_signers"];
  NSString* allowedSigners = [NSString stringWithFormat:@"bot@example.com %@", publicKey];
  XCTAssertTrue([allowedSigners writeToFile:allowedSignersPath atomically:YES encoding:NSUTF8StringEncoding error:NULL]);

  NSString* allowedSignersConfig = [NSString stringWithFormat:@"gpg.ssh.allowedSignersFile=%@", allowedSignersPath];
  NSString* verifyOutput = [self runGitCLTWithRepository:self.repository command:@"-c", allowedSignersConfig, @"verify-commit", commit.SHA1, nil];
  XCTAssertNotNil(verifyOutput);
}

- (void)testCommitSigningFailsOnSignerFailure {
  NSString* signer = _CreateFakeSSHSigner(self.temporaryPath, 7);
  NSString* signingKey = @"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFailingSignerKey test@example.com";

  XCTAssertNotNil(signer);
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"commit.gpgsign", @"true"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.format", @"ssh"));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"gpg.ssh.program", signer));
  XCTAssertTrue(_WriteLocalConfigOption(self.repository, @"user.signingkey", signingKey));
  [self updateFileAtPath:@"failing-signer.txt" withString:@"failing signer\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"failing-signer.txt" error:NULL]);

  NSError* error;
  XCTAssertNil(_CreateCommitFromRepositoryIndex(self.repository, @"Failing signer", &error));
  XCTAssertTrue([error.localizedDescription containsString:@"non-zero status"]);
}

@end
