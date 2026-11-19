import sh.tinfoil.go.mobile.ConfigAuthorizer;
import sh.tinfoil.go.mobile.Mobile;
import sh.tinfoil.go.mobile.Verifier;

// Compiles against the supported Java-facing API of TinfoilGo.aar. Nothing
// here runs: CI only invokes javac, so this proves that the surface exists
// with the expected signatures, and nothing more. In particular it cannot
// detect a change to the JSON contract, which is verificationJSON in
// mobile/verification.go.
final class Smoke {
    static void checkMobileSurface() throws Exception {
        long schemaVersion = Mobile.VerificationSchemaVersion;

        // Options travel as JSON (see mobile/options.go). An empty string
        // selects the default policy.
        String publicRegistry = Mobile.PublicRegistryID;
        Verifier verifier = Mobile.newVerifier("{}");

        // A config authorizer is a Java object that Go calls back during
        // verify, possibly on several threads at once.
        Verifier authorizing = Mobile.newVerifierWithConfigAuthorizer("", new SmokeAuthorizer());

        // The caller fetches the document itself, with a fresh nonce per
        // fetch. A relay is a host with an optional port, not a URL; ""
        // fetches directly.
        byte[] nonce = Mobile.newNonce();
        String url = Mobile.attestationURL("enclave.example", "relay.example:8443", nonce);

        // Checks a client makes before any I/O.
        boolean callerAuthorizes = verifier.callerAuthorizesConfig();
        verifier.checkPinVerifiability("org/repo", "");

        // Verifying performs no I/O; it appraises the fetched bytes.
        String payload = verifier.verify(new byte[0], nonce, "org/repo", "");

        // Errors cross as java.lang.Exception with only a message; the prefix
        // is the category.
        String[] prefixes = {Mobile.UsageErrorPrefix, Mobile.VerificationErrorPrefix};
    }

    private static final class SmokeAuthorizer implements ConfigAuthorizer {
        @Override
        public void authorizeConfig(String endorsementJSON) throws Exception {
            throw new Exception("rejected");
        }
    }

    private Smoke() {}
}
