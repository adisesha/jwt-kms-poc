package me.poc.jwtkms

import com.auth0.jwt.JWT
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class JwtServiceTest {
    @Autowired
    private lateinit var jwtService: JwtService

    @Test
    fun authenticateAndVerify() {
        val username = "test"
        val req = AuthRequest(username, "password")
        val res = jwtService.authenticate(req)
        val decodedJwt = JWT.decode(res.body!!.token)
        assertEquals(username, decodedJwt.subject)

        //Verification
        var verifyResponse = jwtService.verify(TokenHolder(decodedJwt.token))
        assertTrue(verifyResponse.statusCode.is2xxSuccessful)

        //Test with some random token
        val invalidToken =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUs" +
                    "ImlhdCI6MTUxNjIzOTAyMiwianRpIjoidGVzdCJ9.I7tx99TVvFd3vrwQ4vaLO5tnAzi5VxHgUCf9jHU95-qsCbe1BAggJCGdtwA-J_Tcsi" +
                    "6JEFlmDi_nJ3bNr3OAKqUfFPB94hbGBXMTtohIHzPHaMJLQL1dlJT4PHLklNfIOthNsOIifGUvM9PX_7e5jR-3kUeBO5IDawUwP6YtCe4I" +
                    "Rfpbzy5egGPeGnqCICcsyHNruR6yB-X933mhZ1JkoipRW-BFjMT1t7yut9-Hyuuku-XoVe6u2B1Tm9y3c8FOhMiDZcoajSaASWc3wbh1cDPy" +
                    "-9eb0GRntWJsh7qfKn6Vn3C_KK0rgxQg66SAzW5wpfihXRO8lByc9iwXHmsm1w"
        verifyResponse = jwtService.verify(TokenHolder(invalidToken))
        assertTrue(verifyResponse.statusCode.is4xxClientError)
    }

    @Test
    fun revoke(){
        val username = "testrevoke"
        val req = AuthRequest(username, "password")
        val res = jwtService.authenticate(req)
        val decodedJwt = JWT.decode(res.body!!.token)
        var revokeRes = jwtService.revoke(TokenHolder(decodedJwt.token))
        assertTrue(revokeRes.statusCode.is2xxSuccessful)
        revokeRes = jwtService.revoke(TokenHolder(decodedJwt.token))
        assertTrue(revokeRes.statusCode.is4xxClientError)
    }
}