package me.poc.jwtkms

import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class TokenServiceTest{
    @Autowired
    private lateinit var  tokenService: TokenService
    @Test
    fun authenticate(){
        val req = AuthRequest("username", "password")
        val res =tokenService.authenticate(req)
        val decodedJwt = SignedJWT.parse(res.body!!.token)
        assertEquals("username", decodedJwt.jwtClaimsSet.subject)
    }
}