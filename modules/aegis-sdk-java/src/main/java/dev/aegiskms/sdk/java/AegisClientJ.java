package dev.aegiskms.sdk.java;

import dev.aegiskms.sdk.WireFormats;
import dev.aegiskms.sdk.javadsl.AegisJavaClient;

import java.util.List;
import java.util.Map;

/**
 * Java client for the Aegis-KMS REST surface. Thin delegate over the Scala SDK's
 * {@code javadsl.AegisJavaClient}: {@code java.util} collections in, wire DTOs out,
 * failures thrown as {@code dev.aegiskms.sdk.javadsl.AegisClientException}.
 *
 * <pre>{@code
 * AegisClientJ client = AegisClientJ.https("https://aegis.example.com", jwt);
 * WireFormats.ManagedKeyDto key = client.createKey("invoice-2026", "AES", 256);
 * client.activateKey(key.id());
 * }</pre>
 */
public final class AegisClientJ {

    private final AegisJavaClient delegate;

    private AegisClientJ(AegisJavaClient delegate) {
        this.delegate = delegate;
    }

    /** Connect with a bearer JWT — the production path. */
    public static AegisClientJ https(String baseUrl, String token) {
        return new AegisClientJ(AegisJavaClient.https(baseUrl, token));
    }

    /**
     * Connect to a dev-mode server ({@code AEGIS_AUTH_KIND=dev}) identifying via the
     * {@code X-Aegis-User} header. Workstation use only — dev auth performs no verification.
     */
    public static AegisClientJ dev(String baseUrl, String principal) {
        return new AegisClientJ(AegisJavaClient.dev(baseUrl, principal));
    }

    public WireFormats.ManagedKeyDto createKey(String name, String algorithm, int sizeBits) {
        return delegate.createKey(name, algorithm, sizeBits);
    }

    public WireFormats.ManagedKeyDto getKey(String id) {
        return delegate.getKey(id);
    }

    public WireFormats.ManagedKeyDto activateKey(String id) {
        return delegate.activateKey(id);
    }

    public void destroyKey(String id) {
        delegate.destroyKey(id);
    }

    public WireFormats.SignResponse sign(String id, String messageBase64, String algorithm) {
        return delegate.sign(id, messageBase64, algorithm);
    }

    public boolean verify(String id, String messageBase64, String signatureBase64, String algorithm) {
        return delegate.verify(id, messageBase64, signatureBase64, algorithm);
    }

    public WireFormats.EncryptResponse encrypt(String id, String plaintextBase64, Map<String, String> context) {
        return delegate.encrypt(id, plaintextBase64, context);
    }

    public WireFormats.DecryptResponse decrypt(String id, String ciphertextBase64, Map<String, String> context) {
        return delegate.decrypt(id, ciphertextBase64, context);
    }

    public WireFormats.WrapResponse wrap(String id, String dekBase64) {
        return delegate.wrap(id, dekBase64);
    }

    public WireFormats.UnwrapResponse unwrap(String id, String wrappedDekBase64) {
        return delegate.unwrap(id, wrappedDekBase64);
    }

    public WireFormats.ManagedKeyDto compromiseKey(String id, String reason) {
        return delegate.compromiseKey(id, reason);
    }

    public WireFormats.ManagedKeyDto rotateKey(String id, String policy) {
        return delegate.rotateKey(id, policy);
    }

    /** Mint a short-lived agent JWT. {@code parent} may be null to default to the calling principal. */
    public WireFormats.IssueAgentResponseDto issueAgent(String label, List<String> scopes, long ttlSeconds, String parent) {
        return delegate.issueAgent(label, scopes, ttlSeconds, parent);
    }
}
