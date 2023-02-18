package me.poc.jwtkms

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import org.apache.commons.codec.binary.Hex
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import software.amazon.awssdk.core.SdkBytes
import software.amazon.awssdk.services.kms.KmsClient
import software.amazon.awssdk.services.kms.model.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import java.util.regex.Pattern

/**
 * Provides REST stateless services to manage JWT token.
 *
 * @see "https://github.com/auth0/java-jwt"
 * @see "https://jwt.io/introduction"
 */

@RestController
@RequestMapping("/")
class TokenService(
    @Value("\${jwt.issuer}")
    private val jwtIssuer: String,
    private val jwsSigner: KmsSigner
) {
    // Initialized in init block
    private val usernameValidPattern = "[a-zA-Z0-9]{1,10}"
    private val secureRandom = SecureRandom()

    @PostMapping("/authenticate")
    fun authenticate(authRequest: AuthRequest): ResponseEntity<AuthResponse> {
        //As it's an authentication simulation we explicitly ignore the password here...
        //Validate the login parameter content to avoid malicious input
        return if (Pattern.matches(usernameValidPattern, authRequest.username)) {
            //Generate a random string that will constitute the fingerprint for this user
            val randomFgp = ByteArray(50)
            secureRandom.nextBytes(randomFgp)
            val userFingerprint = String(Hex.encodeHex(randomFgp))

            //Add the fingerprint in a hardened cookie - Add cookie manually because SameSite attribute is not supported by javax.servlet.http.Cookie class
            val fingerprintCookie = "__Secure-Fgp=$userFingerprint; SameSite=Strict; HttpOnly; Secure"
            val headers = HttpHeaders()
            headers.add(HttpHeaders.SET_COOKIE, fingerprintCookie)

            //Compute a SHA256 hash of the fingerprint in order to store the fingerprint hash (instead of the raw value) in the token
            //to prevent an XSS to be able to read the fingerprint and set the expected cookie itself
            val digest = MessageDigest.getInstance("SHA-256")
            val userFingerprintDigest = digest.digest(userFingerprint.toByteArray(StandardCharsets.UTF_8))
            val userFingerPrintHash = String(Hex.encodeHex(userFingerprintDigest))

            //Create the token with a validity of 15 minutes and client context (fingerprint) information
            val c = Calendar.getInstance()
            val now = c.time
            c.add(Calendar.MINUTE, 15)
            val expirationDate = c.time

            val payload = JWTClaimsSet.Builder()
                .subject(authRequest.username)
                .expirationTime(expirationDate)
                .issuer(jwtIssuer)
                .issueTime(now)
                .notBeforeTime(now)
                .claim("userFingerprint", userFingerPrintHash)
                .build().toPayload()

            val jwsHeader = JWSHeader.Builder(JWSAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.name))
                .type(JOSEObjectType.JWT)
                .build()

            val jwsObject = JWSObject(jwsHeader, payload)
            jwsObject.sign(jwsSigner)
            ResponseEntity.ok(
                AuthResponse(
                    status = "OK",
                    token = jwsObject.serialize()
                )
            )
        } else {
            ResponseEntity.badRequest().body(AuthResponse(status = "Invalid parameter provided"))
        }
    }


}

@Component
class KmsSigner(private val kmsClient: KmsClient) : BaseJWSProvider(
    setOf(
        JWSAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.name)
    )
), JWSSigner {
    private val signVerifyKeyId: String
    init {
        // Generate RSA key pairs . The private key is used for signing JWT
        // The public key is used for verifying JWT
        val keyRequest = CreateKeyRequest
            .builder()
            .keyUsage(KeyUsageType.SIGN_VERIFY)
            .keySpec(KeySpec.RSA_2048)
            .build()
        val keyResponse = kmsClient.createKey(keyRequest)
        signVerifyKeyId = keyResponse.keyMetadata().keyId()
    }

    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
        val signRequest = SignRequest.builder()
            .keyId(signVerifyKeyId)
            .messageType(MessageType.RAW)
            .message(SdkBytes.fromByteArray(signingInput))
            .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PSS_SHA_256)
            .build()
        val signResponse = kmsClient.sign(signRequest)
        return Base64URL.encode(signResponse.signature().asByteArray())
    }
}