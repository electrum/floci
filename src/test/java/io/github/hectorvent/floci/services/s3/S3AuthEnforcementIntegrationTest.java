package io.github.hectorvent.floci.services.s3;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

@QuarkusTest
@TestProfile(S3AuthEnforcementIntegrationTest.S3AuthProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class S3AuthEnforcementIntegrationTest {

    private static final String PUBLIC_BUCKET = "auth-public-bucket";
    private static final String PRIVATE_BUCKET = "auth-private-bucket";
    private static final String PUBLIC_KEY = "public.txt";
    private static final String PRIVATE_KEY = "private.txt";
    private static final String LOCAL_AUTH_HEADER =
            "AWS4-HMAC-SHA256 Credential=test/20260701/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test";
    private static final String BAD_AUTH_HEADER =
            "AWS4-HMAC-SHA256 Credential=bad-key/20260701/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test";

    @Test
    @Order(1)
    void createBucketsAndObjects() {
        given().when().put("/" + PUBLIC_BUCKET).then().statusCode(200);
        given().when().put("/" + PRIVATE_BUCKET).then().statusCode(200);

        given()
            .body("public body")
        .when()
            .put("/" + PUBLIC_BUCKET + "/" + PUBLIC_KEY)
        .then()
            .statusCode(200);

        given()
            .body("private body")
        .when()
            .put("/" + PRIVATE_BUCKET + "/" + PRIVATE_KEY)
        .then()
            .statusCode(200);

        given()
            .contentType("application/json")
            .body(publicReadPolicy(PUBLIC_BUCKET))
        .when()
            .put("/" + PUBLIC_BUCKET + "?policy")
        .then()
            .statusCode(200);
    }

    @Test
    @Order(2)
    void unsignedRequestCanReadPublicObject() {
        given()
        .when()
            .get("/" + PUBLIC_BUCKET + "/" + PUBLIC_KEY)
        .then()
            .statusCode(200)
            .body(equalTo("public body"));

        given()
        .when()
            .head("/" + PUBLIC_BUCKET + "/" + PUBLIC_KEY)
        .then()
            .statusCode(200);
    }

    @Test
    @Order(3)
    void unsignedRequestCanListPublicBucket() {
        given()
        .when()
            .get("/" + PUBLIC_BUCKET + "?list-type=2")
        .then()
            .statusCode(200)
            .body(containsString("<Key>" + PUBLIC_KEY + "</Key>"));
    }

    @Test
    @Order(4)
    void unsignedRequestCannotReadPrivateObject() {
        given()
        .when()
            .get("/" + PRIVATE_BUCKET + "/" + PRIVATE_KEY)
        .then()
            .statusCode(403)
            .body(containsString("AccessDenied"));

        given()
        .when()
            .head("/" + PRIVATE_BUCKET + "/" + PRIVATE_KEY)
        .then()
            .statusCode(403);
    }

    @Test
    @Order(5)
    void unsignedRequestCannotListPrivateBucket() {
        given()
        .when()
            .get("/" + PRIVATE_BUCKET + "?list-type=2")
        .then()
            .statusCode(403)
            .body(containsString("AccessDenied"));
    }

    @Test
    @Order(6)
    void signedRequestWithBadAccessKeyCannotUsePublicAccess() {
        given()
            .header("Authorization", BAD_AUTH_HEADER)
        .when()
            .get("/" + PUBLIC_BUCKET + "/" + PUBLIC_KEY)
        .then()
            .statusCode(403)
            .body(containsString("InvalidAccessKeyId"));
    }

    @Test
    @Order(7)
    void signedRequestWithLocalAccessKeyCanReadPrivateObject() {
        given()
            .header("Authorization", LOCAL_AUTH_HEADER)
        .when()
            .get("/" + PRIVATE_BUCKET + "/" + PRIVATE_KEY)
        .then()
            .statusCode(200)
            .body(equalTo("private body"));
    }

    private static String publicReadPolicy(String bucket) {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Effect": "Allow",
                      "Principal": "*",
                      "Action": ["s3:GetObject"],
                      "Resource": ["arn:aws:s3:::%s/*"]
                    },
                    {
                      "Effect": "Allow",
                      "Principal": "*",
                      "Action": ["s3:ListBucket"],
                      "Resource": ["arn:aws:s3:::%s"]
                    }
                  ]
                }
                """.formatted(bucket, bucket);
    }

    public static final class S3AuthProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.s3.enforce-auth", "true");
        }
    }
}
