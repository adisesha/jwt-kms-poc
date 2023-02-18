package me.poc.jwtkms

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.testcontainers.containers.localstack.LocalStackContainer
import org.testcontainers.utility.DockerImageName
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.kms.KmsClient


/**
 * Provides AWS KMS client. Uses local stack container to run AWS KMS service locally.
 */
@Configuration
class AwsConfig {

    @Bean
    fun kmsClient(localstack: LocalStackContainer): KmsClient = KmsClient.builder()
        .endpointOverride(localstack.getEndpointOverride(LocalStackContainer.Service.KMS))
        .region(Region.AP_SOUTH_1)
        .credentialsProvider {
            AwsBasicCredentials.create(localstack.accessKey, localstack.secretKey)
        }
        .build()

    @Bean(destroyMethod = "stop")
    fun localStackContainer(): LocalStackContainer {
        // Pay attention to the version of localstack image. Older versions may not support all KMS operations.
        val localStackContainer = LocalStackContainer(DockerImageName.parse("localstack/localstack:1.4.0"))
            .withServices(LocalStackContainer.Service.KMS)
        localStackContainer.start()
        return localStackContainer
    }
}