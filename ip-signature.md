# Signed IP check

A measurement server (rmbtd) answers `POST /ip` with the client's address as seen on the
TCP connection. The client sends the test token of its running test, and the answer is signed
with the key of the control server that issued that token. That control server can then trust
the address for that test, and only for that test.

## Measurement server: request and response

```http
POST /ip HTTP/1.1
Content-Type: application/json

{"token":"f71d53f4-c67c-4b99-b319-979f714cd408_1761903363_q3m…=_#v2#ZQRW…==","client_ip_local":"192.168.1.5"}
```

```json
{"v":"4","ip":"203.0.113.7","nat_type":"nat_local_to_public_ipv4","matching_ip":true,
 "signature":"…"}
```

| Field | Meaning |
|---|---|
| `token` (request) | **Mandatory.** The `test_token` from `/testRequest`, unchanged, as used for the speed test: `<open_test_uuid>_<test_slot>_<HMAC-SHA1>` optionally followed by `_#v2#<base64>`. Missing or blank: 400. |
| `client_ip_local` (request) | Optional; only used for `nat_type`. Not signed, because the client supplies it. |
| other request fields | Ignored (e.g. `test_uuid`, `client_uuid`, the former `open_test_uuid`). |
| `ip` | The TCP peer address in canonical text form. IPv4 that reaches a dual-stack listener as `::ffff:a.b.c.d` is reported as IPv4. The client cannot set it. |
| `matching_ip` | `true` if the v2 part of the token is valid for `ip` (checked with the key that validated v1), i.e. the control server issued the token for the address this server sees. `false` if it differs (typically the other address family, or behind a different NAT) or if there is no or a broken v2 part. |
| `signature` | 32 bytes, base64 (see below). |

There is no `is_proxy` field, because this server does no VPN or proxy detection.

### Token check

The server checks the token exactly as the speed test does, with one difference: it never waits.

1. **v1 must be valid.** `HMAC-SHA1(key, "<uuid>_<slot>")` must match for one of the keys in
   `secret.key`, and `slot` must lie in the speed test's window (at most 20 s early, at most
   90 s late). Otherwise the request is refused with **403**: invalid HMAC, malformed, too early
   or expired.
2. **The v1 match identifies the key.** Each control server has its own key for this
   measurement server. The key that validates v1 belongs to the control server that issued the
   token, and **that key signs the answer**. Its position in `secret.key` doesn't matter.
3. **v2 is informational.** It is checked only with that same key and only sets `matching_ip`; it
   never causes a rejection.

With `--no-token-check` (no keys loaded) the token is still required but not checked, and the
answer has neither `matching_ip` nor `signature`.

Consequence of the time window: the client has to call `/ip` within 20 s before to 90 s after
the test slot, for example right before or alongside the speed test.

## Signature

```
signature = HMAC-SHA256(key, ip16 ‖ uuid16)          32 bytes of input, 32 bytes out
```

- `key`: the key that validated the token's v1 part, as UTF-8 bytes. This is the control
  server's `test_server.key` for this measurement server.
- `ip16`: the address as 16 bytes. IPv6 as-is; IPv4 as IPv4-mapped IPv6 `::ffff:a.b.c.d`, the
  same mapping as `RmbtUdpTokenFactory.toMappedIpv6Bytes`.
- `uuid16`: the open test UUID at the start of the token, as 16 bytes, big-endian (Java:
  most-significant `long`, then least-significant `long`). The token contains it without the
  `O` prefix, and the `O` is not signed.

`matching_ip` is not signed. The control server doesn't need it, because it can compare the signed
`ip` with the address it issued the token for (`test.client_public_ip`).

Test vector, computed independently by the Rust implementation and by the Java verifier below:

```
key       = "testkey12345"
ip        = 203.0.113.1   (ip16 = ::ffff:203.0.113.1)
uuid      = f71d53f4-c67c-4b99-b319-979f714cd408
signature = HVDXiyb2awlRvPhVIx5y/ERz113y0rnCMCHyU2ktAcA=
```

### No salt

There is no salt. The open test UUID is random and unique per test, so it already makes the
HMAC input unique, and the control server checks `ip` and `uuid` directly. A repeated request
for the same IP and test returns the same signature, which proves nothing new.

The two fields are concatenated, not XORed, so the signature binds exactly this IP and this test.

## Control server: verifier (Java)

Drop-in for `at.rtr.rmbt.utils`, next to `RmbtUdpTokenFactory`. This exact code was compiled
and run against live answers from rmbtd over IPv4 and IPv6, with tokens built the way
`TestSettingsFacade` builds them, by two "control servers" with different keys. Signatures
verify with the issuing key only, and a change of UUID or IP is rejected.

```java
package at.rtr.rmbt.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Verifies the signature a measurement server (rmbtd) adds to its {@code POST /ip} answer
 * for a request carrying a valid test token:
 *
 * <pre>
 *   signature = HMAC-SHA256(key, ip16 ‖ uuid16)
 * </pre>
 *
 * {@code key} is the measurement server's secret ({@code test_server.key}), {@code ip16} the
 * signed address as 16 bytes (IPv4 as
 * IPv4-mapped IPv6, as in the v2 token) and {@code uuid16} the open test UUID as 16 bytes
 * (big-endian, without the "O" prefix).
 */
public final class IpSignatureVerifier {

    public static final int SIGNATURE_LENGTH = 32;

    private IpSignatureVerifier() {
    }

    /**
     * @return true if {@code signature} is valid for {@code ip} and {@code openTestUuid}
     *         under {@code key}; false for any malformed input
     */
    public static boolean verify(final String key, final UUID openTestUuid, final InetAddress ip,
                                 final byte[] signature) {
        if (key == null || openTestUuid == null || ip == null
                || signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        // Constant-time comparison: no timing hints about how much of a guess was right.
        return MessageDigest.isEqual(sign(key, openTestUuid, ip), signature);
    }

    /** Computes the signature; the measurement server does the same in Rust. */
    static byte[] sign(final String key, final UUID openTestUuid, final InetAddress ip) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(toMappedIpv6Bytes(ip));
            mac.update(ByteBuffer.allocate(16)
                    .putLong(openTestUuid.getMostSignificantBits())
                    .putLong(openTestUuid.getLeastSignificantBits())
                    .array());
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** Same mapping as {@code RmbtUdpTokenFactory.toMappedIpv6Bytes}. */
    static byte[] toMappedIpv6Bytes(final InetAddress ip) {
        if (ip instanceof Inet6Address) {
            return ip.getAddress();
        }
        if (ip instanceof Inet4Address) {
            final byte[] mapped = new byte[16];
            mapped[10] = (byte) 0xff;
            mapped[11] = (byte) 0xff;
            System.arraycopy(ip.getAddress(), 0, mapped, 12, 4);
            return mapped;
        }
        throw new IllegalArgumentException("Unsupported IP address type: " + ip);
    }
}
```

In the control server, `toMappedIpv6Bytes` can be dropped in favour of the existing
`RmbtUdpTokenFactory.toMappedIpv6Bytes`, which is package-private in the same package.

Unit test for the vector above:

```java
@Test
void verifiesReferenceVector() {
    UUID uuid = UUID.fromString("f71d53f4-c67c-4b99-b319-979f714cd408");
    byte[] sig = Base64.getDecoder().decode("HVDXiyb2awlRvPhVIx5y/ERz113y0rnCMCHyU2ktAcA=");
    assertTrue(IpSignatureVerifier.verify("testkey12345", uuid, InetAddresses.forString("203.0.113.1"), sig));
    assertFalse(IpSignatureVerifier.verify("testkey12345", uuid, InetAddresses.forString("203.0.113.2"), sig));
}
```

## Integration into the control server

### Today's flow

1. **`POST /testRequest`** (`TestSettingsFacade`) creates the `Test` row with status `STARTED`,
   a random `uuid` and `open_test_uuid`, and the assigned `test_server` (`Test.testServer`,
   `server_id`). It returns `test_uuid`, `open_test_uuid` (as `"O" + uuid`) and the test token:
   `<open_test_uuid>_<test_slot>_<HMAC-SHA1>_#v2#<…>`, signed with `testServer.getKey()`, the v2
   part bound to the client address this control server saw.
2. The client runs the measurement against that server, using the token.
3. **`POST /result`** (`ResultServiceImpl.processResultRequest`) locks the row
   (`findAndLockByUuidOrOpenTestUuid`), requires status `STARTED`, stores the result and sets
   the status to `FINISHED` (or an error status) in the same transaction.

### New step in between

Between 1 and 3, within the token's time window, the client calls `/ip` on the **assigned**
measurement server, once per address family, through its existing per-family host names
(`test_server.web_address_ipv4` / `web_address_ipv6`, e.g. `vie3-httpv4.netztest.at`). It sends
the same token it uses for the speed test:

```
POST https://{web_address_ipv4}/ip   {"token":"<test_token>"}   → signed IPv4 answer
POST https://{web_address_ipv6}/ip   {"token":"<test_token>"}   → signed IPv6 answer (if the client has IPv6)
```

`matching_ip` tells the client right away whether the speed test's v2 IP binding will hold for that
family. A failed call (e.g. no IPv6) just means there is no signature for that family.

### How the signatures reach the control server: two options

**A) As part of `/result` (recommended).** Add one optional field to `ResultRequest`:

```json
"ip_signatures": [
  {"ip":"203.0.113.7", "signature":"…"},
  {"ip":"2001:db8::7", "signature":"…"}
]
```

The client copies `ip` and `signature` unchanged from the `/ip` answers. Verification
runs inside `processResultRequest`, after the existing lock and `STARTED` check, with the key
this control server stores for the assigned measurement server:

```java
// ResultRequest — same style as the existing nested lists (e.g. pings)
@JsonProperty(value = "ip_signatures")
private final List<IpSignatureRequest> ipSignatures;

// IpSignatureRequest (new, @Builder @Getter like ResultRequest)
@JsonProperty("ip")        private final String ip;
@JsonProperty("signature") private final String signature;  // base64, 32 bytes

// ResultServiceImpl.processResultRequest — after verifyTestStatus(...)
processIpSignatures(resultRequest, test);

private void processIpSignatures(ResultRequest resultRequest, Test test) {
    final List<IpSignatureRequest> signatures = resultRequest.getIpSignatures();
    if (signatures == null || signatures.isEmpty() || test.getTestServer() == null) {
        return;
    }
    if (signatures.size() > 2) {
        log.warn("test {}: {} ip signatures, expected at most 2 - ignored", test.getUuid(), signatures.size());
        return;
    }
    final String key = test.getTestServer().getKey();
    for (IpSignatureRequest s : signatures) {
        try {
            final InetAddress ip = InetAddresses.forString(s.getIp());
            final boolean valid = IpSignatureVerifier.verify(key, test.getOpenTestUuid(), ip,
                    Base64.getDecoder().decode(s.getSignature()));
            if (!valid) {
                log.warn("test {}: invalid ip signature for {}", test.getUuid(), HelperFunctions.anonymizeIp(ip));
                continue;
            }
            if (ip instanceof Inet4Address && test.getClientPublicIpV4Verified() == null) {
                test.setClientPublicIpV4Verified(InetAddresses.toAddrString(ip));
                test.setClientPublicIpV4VerifiedAnonymized(HelperFunctions.anonymizeIp(ip));
            } else if (ip instanceof Inet6Address && test.getClientPublicIpV6Verified() == null) {
                test.setClientPublicIpV6Verified(InetAddresses.toAddrString(ip));
                test.setClientPublicIpV6VerifiedAnonymized(HelperFunctions.anonymizeIp(ip));
            }
        } catch (IllegalArgumentException e) {  // bad IP literal or bad base64
            log.warn("test {}: malformed ip signature: {}", test.getUuid(), e.getMessage());
        }
    }
}
```

**B) A separate request between test request and result.** For example
`POST /ipSignature {"test_uuid":"…","ip_signatures":[…]}`, analogous to the control server's own
`/ip`, which already looks the test up by `test_uuid`, requires `STARTED` and stores
`nat_type_v4`/`v6`. It needs its own endpoint, lookup, lock and status check. It also adds a
round trip and an error path for the client, and a submission can still arrive after `/result`
(then it is rejected because the status is no longer `STARTED`).

**Recommendation: A.** The "in between" part of the flow is the client's call to the measurement
server. Delivering the result piggybacks on `/result`, which already has the right lock, the
`STARTED` check and the status change. That makes each signature single-use without any extra
state. Option B is only worth it if the verified IP is needed **before** the result arrives
(e.g. for an operator lookup shown during the test).

### Storage

New columns on `test`, for example:

```sql
ALTER TABLE test
    ADD COLUMN client_public_ip_v4_verified            text,
    ADD COLUMN client_public_ip_v4_verified_anonymized text,
    ADD COLUMN client_public_ip_v6_verified            text,
    ADD COLUMN client_public_ip_v6_verified_anonymized text;
```

Flyway is disabled in `application.yml` (`spring.flyway.enabled: false`; only
`src/test/resources/db/migration/V1__init_db.sql` exists), so this has to be applied as a manual
SQL script, like other schema changes. The existing `client_public_ip` (seen by the control
server at `/testRequest`) and `source_ip` (seen at `/result`) stay unchanged. The new columns
add what the measurement server saw, with a proof. Only the anonymized variants belong in open
data, as with the existing IP columns.

### Failure policy

A missing, malformed or invalid signature must **not** fail the result. The measurement is
still valid; it just has no verified IP. Store nothing for that family and log a warning.

### Replay analysis

| Attempt | Outcome |
|---|---|
| Reuse a signature for another test | Fails: `uuid16` is that test's `open_test_uuid`. |
| Collect signatures before a test | Impossible: `/ip` needs a valid token, which only exists after `/testRequest`. |
| Get a signature long after the test slot | Refused by the measurement server (token time window, 90 s late at most). |
| Reuse it after the test | Refused by the control server: the status is no longer `STARTED`. The `open_test_uuid` does become public in open data, but only once the test has finished. |
| Submit it twice in the same test | Harmless: it is the same IP for the same test, and `/result` runs only once. |
| Claim a different IP | Requires the key (HMAC), and the measurement server signs only the TCP peer address. |
| Signature from another measurement server, or with another control server's key | Fails: verification uses only the key this control server stores for the assigned server. |

There is no timestamp in the signature. Its lifetime is bounded twice: the measurement server
signs only within the token's time window, and the control server accepts only while the test is
`STARTED`.

**Remaining limit (relay):** a client could pass its token to a helper on another network while
the test runs, and the helper's IP gets signed. The signature proves that this IP called `/ip`
with this test's token, not that the IP belongs to the measuring device. Plausibility checks
narrow this down: compare the verified IP of the test's own address family with `source_ip`
and `client_public_ip`, and compare ASN/operator. Flag mismatches rather than reject them.

### Keys and multiple control servers

A measurement server can be shared by several control servers. Each stores its own key for it in
`test_server.key`, and all of these keys are listed in the measurement server's `secret.key`.
The token's v1 HMAC identifies which control server issued the token. The answer is signed with
exactly that key, so only the issuing control server can verify it, and verifying needs no key
ID: `test.getTestServer().getKey()`. The order of keys in `secret.key` is irrelevant.

### Rollout and compatibility

- **Clients first:** Spring Boot's Jackson default ignores unknown JSON properties, and no
  override of that was found in the control server. A client can therefore send
  `ip_signatures` before the control server supports it.
- **Old measurement servers:** they have no `/ip` (the request gets a 426), or they are the
  intermediate version that expected `open_test_uuid` instead of `token`. The client then has
  no signature for that family and sends nothing.
- **Old clients:** they send no `ip_signatures`, so nothing changes.
- **Rollout order:** measurement servers (done), control server (verifier, columns, Option A),
  then clients (two `/ip` calls with the token, `ip_signatures` in `/result`).
