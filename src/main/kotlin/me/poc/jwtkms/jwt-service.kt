package me.poc.jwtkms

import com.auth0.jwt.HeaderParams
import com.auth0.jwt.JWT
import com.auth0.jwt.RegisteredClaims
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import software.amazon.awssdk.core.SdkBytes
import software.amazon.awssdk.services.kms.KmsClient
import software.amazon.awssdk.services.kms.model.*
import java.nio.charset.StandardCharsets
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
class JwtService(
    private val kmsClient: KmsClient,
    @Value("\${jwt.issuer}")
    private val jwtIssuer: String,
    private val objectMapper: ObjectMapper
) {
    // Initialized in init block
    private val signVerifyKeyId: String
    private val usernameValidPattern = "[a-zA-Z0-9]{1,10}"

    //Storing revoked tokens in memory is not a good idea in a real world application
    private val revokedTokens = mutableSetOf<String>()

    // Encoder and decoders are thread safe
    private val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
    private val base64UrlDecoder = Base64.getUrlDecoder()

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
        if (!Pattern.matches(usernameValidPattern, authRequest.username)) {
            return ResponseEntity.badRequest().body(AuthResponse(status = "Invalid parameter provided"))
        }

        return try {
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
                RegisteredClaims.JWT_ID to UUID.randomUUID().toString(),
            )
            val headerClaims = mapOf(
                HeaderParams.TYPE to "JWT",
                HeaderParams.ALGORITHM to "RS256",
            )
            val token = sign(payloadClaims, headerClaims)
            ResponseEntity.ok(AuthResponse(status = "Authentication Successful.", token = token))
        } catch (e: Exception) {
            ResponseEntity.badRequest().body(AuthResponse(status = "Error while creating token"))
        }
    }

    @PostMapping("/verify")
    fun verify(request: TokenHolder): ResponseEntity<String> {
        val jwt = JWT.decode(request.token)
        val jwtId = jwt.getClaim(RegisteredClaims.JWT_ID).asString()
        //Check if token is revoked
        if (revokedTokens.contains(jwtId)) {
            return ResponseEntity.badRequest().body("Token is revoked")
        }

        //Verify signature with KMS
        val signableContent = "${jwt.header}.${jwt.payload}".toByteArray(StandardCharsets.UTF_8)
        val signature = base64UrlDecoder.decode(jwt.signature)
        val kmsVerifyRequest = VerifyRequest.builder()
            .keyId(signVerifyKeyId)
            .message(SdkBytes.fromByteArray(signableContent))
            .signature(SdkBytes.fromByteArray(signature))
            .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
            .build()
        return try {
            kmsClient.verify(kmsVerifyRequest)
            ResponseEntity.ok("Token is valid")
        } catch (e: KmsInvalidSignatureException) {
            ResponseEntity.badRequest().body("Token is invalid")
        }
    }

    @PostMapping("/revoke")
    fun revoke(request: TokenHolder): ResponseEntity<String> {
        //Verify the token before revoking it
        val verifyResponse = verify(request)
        return if (verifyResponse.statusCode.is2xxSuccessful) {
            revokedTokens.add(JWT.decode(request.token).getClaim(RegisteredClaims.JWT_ID).asString())
            ResponseEntity.ok("Token is revoked")
        } else {
            verifyResponse
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
        base64UrlEncoder.encodeToString(payload.toByteArray(StandardCharsets.UTF_8))

    private fun sign(headerBytes: ByteArray, payloadBytes: ByteArray): String {
        val contentBytes = headerBytes + '.'.code.toByte() + payloadBytes
        val signRequest = SignRequest.builder()
            .keyId(signVerifyKeyId)
            .messageType(MessageType.RAW)
            .message(SdkBytes.fromByteArray(contentBytes))
            .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
            .build()
        val signResponse = kmsClient.sign(signRequest)
        return base64UrlEncoder.encodeToString(signResponse.signature().asByteArray())
    }

}