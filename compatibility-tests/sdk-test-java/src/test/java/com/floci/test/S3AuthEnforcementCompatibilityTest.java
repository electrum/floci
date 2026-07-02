package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutBucketPolicyRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("S3 Auth Enforcement")
class S3AuthEnforcementCompatibilityTest {

    private static final String BUCKET = TestFixtures.uniqueName("sdk-s3-auth-enf");
    private static final String KEY = "public.txt";
    private static final String CONTENT = "public content";

    private static S3Client adminS3;
    private static S3Client anonymousS3;
    private static S3Client unknownCredentialS3;
    private static boolean enforcementEnabled;

    @BeforeAll
    static void setup() {
        adminS3 = TestFixtures.s3Client();
        anonymousS3 = s3WithAnonymousCredentials();
        unknownCredentialS3 = s3WithCredentials("bad-key", "bad-secret");

        adminS3.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        adminS3.putObject(PutObjectRequest.builder().bucket(BUCKET).key(KEY).build(),
                RequestBody.fromString(CONTENT));
        adminS3.putBucketPolicy(PutBucketPolicyRequest.builder()
                .bucket(BUCKET)
                .policy(publicReadPolicy())
                .build());

        assertThat(readObject(anonymousS3)).isEqualTo(CONTENT);
        enforcementEnabled = probeEnforcementEnabled();
    }

    @AfterAll
    static void cleanup() {
        close(adminS3);
        close(anonymousS3);
        close(unknownCredentialS3);
    }

    private static void close(S3Client client) {
        if (client != null) {
            client.close();
        }
    }

    @Test
    @DisplayName("public object read rejects unknown signed credentials")
    void publicObjectReadRejectsUnknownSignedCredentials() {
        assumeEnforcementEnabled();

        assertThat(readObject(anonymousS3)).isEqualTo(CONTENT);
        assertThatThrownBy(() -> readObject(unknownCredentialS3))
                .isInstanceOfSatisfying(S3Exception.class, S3AuthEnforcementCompatibilityTest::assertInvalidAccessKey);
    }

    @Test
    @DisplayName("public bucket list rejects unknown signed credentials")
    void publicBucketListRejectsUnknownSignedCredentials() {
        assumeEnforcementEnabled();

        assertThat(anonymousS3.listObjectsV2(ListObjectsV2Request.builder().bucket(BUCKET).build()).contents())
                .anyMatch(object -> KEY.equals(object.key()));
        assertThatThrownBy(() -> unknownCredentialS3.listObjectsV2(
                ListObjectsV2Request.builder().bucket(BUCKET).build()))
                .isInstanceOfSatisfying(S3Exception.class, S3AuthEnforcementCompatibilityTest::assertInvalidAccessKey);
    }

    private static boolean probeEnforcementEnabled() {
        try {
            readObject(unknownCredentialS3);
            return false;
        } catch (S3Exception e) {
            if (e.statusCode() == 403
                    && "InvalidAccessKeyId".equals(e.awsErrorDetails().errorCode())) {
                return true;
            }
            throw e;
        }
    }

    private static void assumeEnforcementEnabled() {
        Assumptions.assumeTrue(enforcementEnabled,
                "S3 auth enforcement is not enabled - set floci.services.s3.enforce-auth=true to run these tests");
    }

    private static String readObject(S3Client client) {
        ResponseBytes<GetObjectResponse> response = client.getObjectAsBytes(
                GetObjectRequest.builder().bucket(BUCKET).key(KEY).build());
        return response.asString(StandardCharsets.UTF_8);
    }

    private static S3Client s3WithAnonymousCredentials() {
        return S3Client.builder()
                .endpointOverride(TestFixtures.endpoint())
                .region(Region.US_EAST_1)
                .credentialsProvider(AnonymousCredentialsProvider.create())
                .forcePathStyle(true)
                .build();
    }

    private static S3Client s3WithCredentials(String accessKeyId, String secretAccessKey) {
        return S3Client.builder()
                .endpointOverride(TestFixtures.endpoint())
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
                .forcePathStyle(true)
                .build();
    }

    private static void assertInvalidAccessKey(S3Exception e) {
        assertThat(e.statusCode()).isEqualTo(403);
        assertThat(e.awsErrorDetails().errorCode()).isEqualTo("InvalidAccessKeyId");
    }

    private static String publicReadPolicy() {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Effect": "Allow",
                      "Principal": "*",
                      "Action": "s3:ListBucket",
                      "Resource": "arn:aws:s3:::%s"
                    },
                    {
                      "Effect": "Allow",
                      "Principal": "*",
                      "Action": "s3:GetObject",
                      "Resource": "arn:aws:s3:::%s/*"
                    }
                  ]
                }
                """.formatted(BUCKET, BUCKET);
    }
}
