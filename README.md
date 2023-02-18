## Introduction

This project is port of [poc-jwt](https://github.com/righettod/poc-jwt). The original project is the code repository of 
[JSON Web Token (JWT) Cheat Sheet for Java.](https://www.owasp.org/index.php/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java). 

Here is how it differs from the original project:
* Kotlin instead of Java
* Authentication, token verification and revocation are implemented as REST services using Spring Web.
* For token signature, RSA is used instead of HMAC. So, adding fingerprint to the token is not implemented. See StackExchange [question](https://security.stackexchange.com/questions/220185/jwt-choosing-between-hmac-and-rsa) for more details.
* Token encryption, to avoid information disclosure, is not implemented. Check the original project for that.

## WARNING
This is a POC. Do not use it in production without fully understanding what the code does. In almost all cases, you are better off relying on a open source framework or a third party authentication providers.

## How to run
You need Java 17 and Docker. The code runs [LocalStack TestContainer](https://www.testcontainers.org/modules/localstack/) to avoid connecting to real AWS services. This requires Docker. See `aws-config.kt` for more details. 
If you want to test against actual KMS service, modify `aws-config.kt`.

To run the code, execute the following command:
```./gradlew bootRun```
To run the tests, execute the following command:
```./gradlew test```


