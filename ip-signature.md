# Signed IP check

A measurement server (rmbtd) answers `POST /ip` with the client's address as seen on the
TCP connection. When the client sends the `open_test_uuid` of its running test, the answer is
signed with the measurement server's secret. The control server can then trust that address
for that test, and only for that test.

## Measurement server: request and response

```http
POST /ip HTTP/1.1
Content-Type: application/json

{"open_test_uuid":"Of71d53f4-c67c-4b99-b319-979f714cd408","client_ip_local":"192.168.1.5"}
```

```json
{"v":"4","ip":"203.0.113.7","nat_type":"nat_local_to_public_ipv4",
 "salt":"D1Hfsm/7IujFU3vlYfh1Tw==","signature":"ABsFHoSDUbkAHIbSZ8HJ+ZdsfCZ2vtppoVCCDuhOenc="}
```

| Field | Meaning |
|---|---|
| `open_test_uuid` (request) | From `/testRequest`. Accepted with or without the leading `O`. Optional; without it the answer is unsigned. An invalid value gives 400. |
| `client_ip_local` (request) | Optional; only used for `nat_type`. Not signed, because the client supplies it. |
| other request fields | Ignored (e.g. `test_uuid`, `client_uuid`). |
| `ip` | The TCP peer address in canonical text form. IPv4 that reaches a dual-stack listener as `::ffff:a.b.c.d` is reported as IPv4. The client cannot set it. |
| `salt` | 16 random bytes (OS RNG), base64; new for every answer. |
| `signature` | 32 bytes, base64 (see below). |

There is no `is_proxy` field, because this server does no VPN or proxy detection. If no key is
loaded (`--no-token-check`), the answer is unsigned.

## Signature

```
signature = HMAC-SHA256(key, salt ‖ ip16 ‖ uuid16)          48 bytes of input, 32 bytes out
```

- `key`: the measurement server's secret as UTF-8 bytes, i.e. the **first** key in
  `secret.key`. It must be the key stored in the control server's `test_server.key` for this
  server. Token validation accepts any listed key; signing always uses the first one.
- `salt`: the 16 bytes from the answer.
- `ip16`: the address as 16 bytes. IPv6 as-is; IPv4 as IPv4-mapped IPv6 `::ffff:a.b.c.d`, the
  same mapping as `RmbtUdpTokenFactory.toMappedIpv6Bytes`.
- `uuid16`: the open test UUID as 16 bytes, big-endian (Java: most-significant `long`, then
  least-significant `long`). The `O` prefix is **not** signed.

Test vector, computed independently by the Rust implementation and by the Java verifier below:

```
key       = "testkey12345"
salt      = 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07   (BwcHBwcHBwcHBwcHBwcHBw==)
ip        = 203.0.113.1                                       (ip16 = ::ffff:203.0.113.1)
uuid      = f71d53f4-c67c-4b99-b319-979f714cd408
signature = rHe5w73IaBy+Yae/MiewbcqDdJzFZnMaizqbKZLQRj4=
```

### Why concatenation and not `salt ⊕ ip ⊕ uuid`

With XOR the three values collapse into one 16-byte HMAC input, and the client both learns and
supplies the salt. From one valid answer `(salt, ip, uuid, sig)` a client could compute
`salt' = salt ⊕ ip ⊕ uuid ⊕ ip' ⊕ uuid'` for **any** IP `ip'` and **any** test `uuid'`. The HMAC
input `salt' ⊕ ip' ⊕ uuid'` would equal the original, so `sig` would verify: a single signature
could be forged for every IP and every test. Concatenation keeps the fields separate, so the
signature binds exactly this salt, this IP and this test.

The salt makes every answer unique: the same IP and test get a new signature each time. Since
the control server checks `ip` and `uuid` directly, the salt adds no security of its own, but
it does no harm either.

## Control server: verifier (Java)

Drop-in for `at.rtr.rmbt.utils`, next to `RmbtUdpTokenFactory`. This exact code was compiled
and run against live answers from rmbtd over IPv4 and IPv6: valid signatures verify, and a
change of UUID, IP, key or salt is rejected.

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
 * when the client sends its {@code open_test_uuid}:
 *
 * <pre>
 *   signature = HMAC-SHA256(key, salt ‖ ip16 ‖ uuid16)
 * </pre>
 *
 * {@code key} is the measurement server's secret ({@code test_server.key}), {@code salt} the
 * 16 random bytes from the answer, {@code ip16} the signed address as 16 bytes (IPv4 as
 * IPv4-mapped IPv6, as in the v2 token) and {@code uuid16} the open test UUID as 16 bytes
 * (big-endian, without the "O" prefix).
 */
public final class IpSignatureVerifier {

    public static final int SALT_LENGTH = 16;
    public static final int SIGNATURE_LENGTH = 32;

    private IpSignatureVerifier() {
    }

    /**
     * @return true if {@code signature} is valid for {@code ip} and {@code openTestUuid}
     *         under {@code key}; false for any malformed input
     */
    public static boolean verify(final String key, final UUID openTestUuid, final InetAddress ip,
                                 final byte[] salt, final byte[] signature) {
        if (key == null || openTestUuid == null || ip == null
                || salt == null || salt.length != SALT_LENGTH
                || signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        // Constant-time comparison: no timing hints about how much of a guess was right.
        return MessageDigest.isEqual(sign(key, openTestUuid, ip, salt), signature);
    }

    /** Computes the signature; the measurement server does the same in Rust. */
    static byte[] sign(final String key, final UUID openTestUuid, final InetAddress ip, final byte[] salt) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(salt);
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
    byte[] salt = new byte[16];
    Arrays.fill(salt, (byte) 7);
    UUID uuid = UUID.fromString("f71d53f4-c67c-4b99-b319-979f714cd408");
    byte[] sig = Base64.getDecoder().decode("rHe5w73IaBy+Yae/MiewbcqDdJzFZnMaizqbKZLQRj4=");
    assertTrue(IpSignatureVerifier.verify("testkey12345", uuid, InetAddresses.forString("203.0.113.1"), salt, sig));
    assertFalse(IpSignatureVerifier.verify("testkey12345", uuid, InetAddresses.forString("203.0.113.2"), salt, sig));
}
```

## Integration into the control server

### Today's flow

1. **`POST /testRequest`** (`TestSettingsFacade`) creates the `Test` row with status `STARTED`,
   a random `uuid` and `open_test_uuid`, and the assigned `test_server` (`Test.testServer`,
   `server_id`). It returns `test_uuid`, `open_test_uuid` (as `"O" + uuid`) and the test token,
   which is signed with `testServer.getKey()`.
2. The client runs the measurement against that server.
3. **`POST /result`** (`ResultServiceImpl.processResultRequest`) locks the row
   (`findAndLockByUuidOrOpenTestUuid`), requires status `STARTED`, stores the result and sets
   the status to `FINISHED` (or an error status) in the same transaction.

### New step in between

Between 1 and 3, the client calls `/ip` on the **assigned** measurement server, once per address
family, through its existing per-family host names (`test_server.web_address_ipv4` /
`web_address_ipv6`, e.g. `vie3-httpv4.netztest.at`):

```
POST https://{web_address_ipv4}/ip   {"open_test_uuid":"O…"}   → signed IPv4 answer
POST https://{web_address_ipv6}/ip   {"open_test_uuid":"O…"}   → signed IPv6 answer (if the client has IPv6)
```

This can run in parallel with the measurement, since it is two small HTTPS requests. A failed
call (e.g. no IPv6) just means there is no signature for that family.

### How the signatures reach the control server: two options

**A) As part of `/result` (recommended).** Add one optional field to `ResultRequest`:

```json
"ip_signatures": [
  {"ip":"203.0.113.7", "salt":"D1Hf…Tw==", "signature":"ABsF…enc="},
  {"ip":"2001:db8::7", "salt":"…",         "signature":"…"}
]
```

The client copies `ip`, `salt` and `signature` unchanged from the `/ip` answers. Verification
runs inside `processResultRequest`, after the existing lock and `STARTED` check:

```java
// ResultRequest — same style as the existing nested lists (e.g. pings)
@JsonProperty(value = "ip_signatures")
private final List<IpSignatureRequest> ipSignatures;

// IpSignatureRequest (new, @Builder @Getter like ResultRequest)
@JsonProperty("ip")        private final String ip;
@JsonProperty("salt")      private final String salt;       // base64, 16 bytes
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
                    Base64.getDecoder().decode(s.getSalt()),
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
| Collect signatures before a test | Impossible: the `open_test_uuid` is random and only exists after `/testRequest`. |
| Reuse it after the test | Refused: the status is no longer `STARTED`. The `open_test_uuid` does become public in open data, but only once the test has finished. |
| Submit it twice in the same test | Harmless: it is the same IP for the same test, and `/result` runs only once. |
| Claim a different IP | Requires the key (HMAC), and the measurement server signs only the TCP peer address. |
| Choose a salt to fit another IP/test | Not possible with concatenation (see the XOR section). |
| Signature from another measurement server | Fails: verification uses only the assigned server's key. |

There is no timestamp in the signature. Its lifetime is the `STARTED` window of the test. If
tests can stay `STARTED` for long, the control server can also ignore signatures in results
that arrive more than N minutes after `test.time`; it already has that time.

**Remaining limit (relay):** a client could pass its `open_test_uuid` to a helper on another
network while the test runs, and the helper's IP gets signed. The signature proves that this IP
called `/ip` for this test, not that the IP belongs to the measuring device. Plausibility checks
narrow this down: compare the verified IP of the test's own address family with `source_ip`
and `client_public_ip`, and compare ASN/operator. Flag mismatches rather than reject them.

### Keys and rotation

The control server verifies with `test.getTestServer().getKey()`, so no key ID is needed in the
answer. The measurement server signs with the first key in `secret.key`. During a key rotation,
that first key must be the one in `test_server.key`; older keys can stay further down in the
file so that tokens issued with them are still accepted.

### Rollout and compatibility

- **Clients first:** Spring Boot's Jackson default ignores unknown JSON properties, and no
  override of that was found in the control server. A client can therefore send
  `ip_signatures` before the control server supports it.
- **Old measurement servers:** they have no `/ip` (the request gets a 426), or they answer
  without a signature. The client then sends nothing for that family.
- **Old clients:** they send no `ip_signatures`, so nothing changes.
- **Rollout order:** measurement servers (done), control server (verifier, columns, Option A),
  then clients (two `/ip` calls, `ip_signatures` in `/result`).
