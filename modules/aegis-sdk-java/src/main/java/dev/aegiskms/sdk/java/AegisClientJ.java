package dev.aegiskms.sdk.java;

/**
 * Java-friendly facade over the Scala SDK. Placeholder during scaffolding;
 * real implementation will wrap {@code dev.aegiskms.sdk.AegisClient} and
 * expose a blocking / CompletableFuture API so Java users never need to
 * reason about Cats Effect.
 */
public final class AegisClientJ {
    private AegisClientJ() { }

    public static AegisClientJ https(String baseUrl, String token) {
        throw new UnsupportedOperationException(
            "AegisClientJ.https is not yet implemented (scaffold)");
    }
}
