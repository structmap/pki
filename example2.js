import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

interface
IssueCertificateOptions
{
    ArrayBuffer | Uint8Array;
    pkijs.Certificate;
    CryptoKey;
    notBefore ? : Date;
    notAfter ? : Date;
    hashAlgorithm ? : string;
}

/**
 * Issues an X.509 v3 certificate from a CSR without domain/SAN validation,
 * ensuring the validity period does not exceed 1 year (365 days).
 */
export async function issueCertificateFromCsr({
                                                  csrDer,
                                                  caCert,
                                                  caPrivateKey,
                                                  notBefore = new Date(),
                                                  notAfter,
                                                  hashAlgorithm = "SHA-256",
                                              }: IssueCertificateOptions): Promise<pkijs.Certificate> {
    const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

    // 1. Determine and enforce validity bounds (< 1 year)
    const targetNotAfter = notAfter ?? new Date(notBefore.getTime() + ONE_YEAR_MS - 1000);
    const requestedDurationMs = targetNotAfter.getTime() - notBefore.getTime();

    if (requestedDurationMs <= 0) {
        throw new Error("Invalid validity period: notAfter must be after notBefore.");
    }

    if (requestedDurationMs >= ONE_YEAR_MS) {
        throw new Error(
            `Certificate duration (${(requestedDurationMs / (24 * 60 * 60 * 1000)).toFixed(1)} days) exceeds the maximum allowed 1-year limit.`
        );
    }

    // 2. Parse and verify CSR integrity
    const csr = pkijs.CertificationRequest.fromBER(csrDer);
    const isCsrValid = await csr.verify();
    if (!isCsrValid) {
        throw new Error("CSR signature verification failed (proof-of-possession invalid).");
    }

    // 3. Initialize target Certificate (X.509 v3)
    const cert = new pkijs.Certificate();
    cert.version = 2; // X.509 v3 corresponds to integer value 2

    // Generate a random positive 64-bit integer serial number
    const serialBytes = new Uint8Array(8);
    crypto.getRandomValues(serialBytes);
    serialBytes[0] &= 0x7f; // Ensure positive integer
    cert.serialNumber = new asn1js.Integer({valueHex: serialBytes.buffer});

    // 4. Directly adopt subject and public key without CN validation
    cert.subject = csr.subject;
    cert.issuer = caCert.subject;
    cert.notBefore.value = notBefore;
    cert.notAfter.value = targetNotAfter;
    cert.subjectPublicKeyInfo = csr.subjectPublicKeyInfo;

    // 5. Transfer requested extensions (such as SAN) without domain filtering
    const extensions: pkijs.Extension[] = [];

    // Standard end-entity basic constraints (CA: FALSE)
    const basicConstraints = new pkijs.BasicConstraints({cA: false});
    extensions.push(
        new pkijs.Extension({
            extnID: pkijs.id_BasicConstraints,
            critical: true,
            extnValue: basicConstraints.toSchema().toBER(),
            parsedValue: basicConstraints,
        })
    );

    // Extract extensionRequest attribute (OID: 1.2.840.113549.1.9.14) from CSR
    if (csr.attributes) {
        for (const attr of csr.attributes) {
            if (attr.type === "1.2.840.113549.1.9.14") {
                for (const value of attr.values) {
                    const extSequence = new pkijs.Extensions({schema: value});
                    for (const ext of extSequence.extensions) {
                        // Include SAN and other requested extensions directly to avoid processing delays
                        if (ext.extnID === pkijs.id_SubjectAltName || ext.extnID === pkijs.id_KeyUsage) {
                            extensions.push(ext);
                        }
                    }
                }
            }
        }
    }

    cert.extensions = extensions;

    // 6. Sign using the CA private key
    await cert.sign(caPrivateKey, hashAlgorithm);

    return cert;
}
