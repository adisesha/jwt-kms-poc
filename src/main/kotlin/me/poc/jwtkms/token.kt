package me.poc.jwtkms

import com.auth0.jwt.HeaderParams
import com.auth0.jwt.RegisteredClaims
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.codec.Hex
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
    private val kmsClient: KmsClient,
    @Value("\${jwt.issuer}")
    private val jwtIssuer: String,
    private val objectMapper: ObjectMapper
) {
    // Initialized in init block
    private val signVerifyKeyId: String
    private val usernameValidPattern = "[a-zA-Z0-9]{1,10}"
    private val secureRandom = SecureRandom()

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

    @PostMapping("/authenticate")
    fun authenticate(authRequest: AuthRequest): ResponseEntity<AuthResponse> {
        //As it's an authentication simulation we explicitly ignore the password here...
        //Validate the login parameter content to avoid malicious input
        return if (Pattern.matches(usernameValidPattern, authRequest.username)) {
            //Generate a random string that will constitute the fingerprint for this user
            val randomFgp = ByteArray(50)
            secureRandom.nextBytes(randomFgp)
            val userFingerprint = String(Hex.encode(randomFgp))

            //Add the fingerprint in a hardened cookie - Add cookie manually because SameSite attribute is not supported by javax.servlet.http.Cookie class
            val fingerprintCookie = "__Secure-Fgp=$userFingerprint; SameSite=Strict; HttpOnly; Secure"
            val headers = HttpHeaders()
            headers.add(HttpHeaders.SET_COOKIE, fingerprintCookie)

            //Compute a SHA256 hash of the fingerprint in order to store the fingerprint hash (instead of the raw value) in the token
            //to prevent an XSS to be able to read the fingerprint and set the expected cookie itself
            val digest = MessageDigest.getInstance("SHA-256")
            val userFingerprintDigest = digest.digest(userFingerprint.toByteArray(StandardCharsets.UTF_8))
            val userFingerPrintHash = String(Hex.encode(userFingerprintDigest))

            //Create the token with a validity of 15 minutes and client context (fingerprint) information
            val c = Calendar.getInstance()
            val now = c.time
            c.add(Calendar.MINUTE, 15)
            val expirationDate = c.time

            val payloadClaims = mapOf(
                RegisteredClaims.SUBJECT to authRequest.username,
                RegisteredClaims.EXPIRES_AT to expirationDate.time,
                RegisteredClaims.ISSUER to jwtIssuer,
                RegisteredClaims.ISSUED_AT to now.time,
                RegisteredClaims.NOT_BEFORE to now.time,
                "userFingerprint" to userFingerPrintHash
            )
            val headerClaims = mapOf(
                HeaderParams.TYPE to "JWT",
                HeaderParams.ALGORITHM to "RS256"
            )
            val token = sign(payloadClaims, headerClaims)
            ResponseEntity.ok(
                AuthResponse(
                    status = "OK",
                    token = token
                )
            )
        } else {
            ResponseEntity.badRequest().body(AuthResponse(status = "Invalid parameter provided"))
        }

    }

    // See com.auth0.jwt.JWTCreator.sign
    private fun sign(payloadClaims: Map<String, Any>, headerClaims: Map<String, Any>): String {
        val headerJson = objectMapper.writeValueAsString(headerClaims)
        val payloadJson = objectMapper.writeValueAsString(payloadClaims)

        val header = encodeBase64UrlSafe(headerJson)
        val payload = encodeBase64UrlSafe(payloadJson)

        val signature = sign(
            header.toByteArray(StandardCharsets.UTF_8),
            payload.toByteArray(StandardCharsets.UTF_8)
        )
        return "$header.$payload.$signature"
    }

    private fun encodeBase64UrlSafe(payload: String): String =
        encodeBase64UrlSafe(payload.toByteArray(StandardCharsets.UTF_8))

    private fun encodeBase64UrlSafe(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(bytes)

    private fun sign(headerBytes: ByteArray, payloadBytes: ByteArray): String {
        val contentBytes = headerBytes + '.'.code.toByte() + payloadBytes
        val signRequest = SignRequest.builder()
            .keyId(signVerifyKeyId)
            .messageType(MessageType.RAW)
            .message(SdkBytes.fromByteArray(contentBytes))
            .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
            .build()
        val signResponse = kmsClient.sign(signRequest)
        return encodeBase64UrlSafe(signResponse.signature().asByteArray())
    }

}