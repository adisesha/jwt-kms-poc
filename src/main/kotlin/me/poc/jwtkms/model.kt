package me.poc.jwtkms

class AuthRequest(val username: String, val password: String)
class AuthResponse(val token: String? = null, val status: String)

class TokenHolder(val token: String)

