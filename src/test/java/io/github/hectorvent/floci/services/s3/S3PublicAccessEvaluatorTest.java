package io.github.hectorvent.floci.services.s3;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class S3PublicAccessEvaluatorTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String BUCKET = "public-bucket";
    private static final String BUCKET_ARN = "arn:aws:s3:::" + BUCKET;
    private static final String OBJECT_ARN = BUCKET_ARN + "/folder/object.txt";

    @Test
    void blankPolicyDoesNotAllow() {
        assertFalse(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, "", "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void invalidJsonDoesNotAllow() {
        assertFalse(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, "{not-json", "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void publicStringPrincipalAllowsMatchingObjectAction() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":"*",
                  "Action":"s3:GetObject",
                  "Resource":"arn:aws:s3:::public-bucket/*"
                }}""";

        assertTrue(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void publicAwsPrincipalAllowsMatchingBucketAction() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":{"AWS":"*"},
                  "Action":["s3:ListBucket"],
                  "Resource":["arn:aws:s3:::public-bucket"]
                }}""";

        assertTrue(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:ListBucket", BUCKET_ARN));
    }

    @Test
    void publicPrincipalArrayAllowsMatchingAction() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":["arn:aws:iam::123456789012:root","*"],
                  "Action":"s3:GetObject",
                  "Resource":"arn:aws:s3:::public-bucket/*"
                }}""";

        assertTrue(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void nonPublicPrincipalDoesNotAllow() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":{"AWS":"arn:aws:iam::123456789012:root"},
                  "Action":"s3:GetObject",
                  "Resource":"arn:aws:s3:::public-bucket/*"
                }}""";

        assertFalse(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void conditionStatementDoesNotAllowAnonymousRead() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":"*",
                  "Action":"s3:GetObject",
                  "Resource":"arn:aws:s3:::public-bucket/*",
                  "Condition":{"StringEquals":{"aws:PrincipalAccount":"123456789012"}}
                }}""";

        assertFalse(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void explicitDenyOverridesAllow() {
        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":"s3:GetObject",
                    "Resource":"arn:aws:s3:::public-bucket/*"
                  },
                  {
                    "Effect":"Deny",
                    "Principal":"*",
                    "Action":"s3:GetObject",
                    "Resource":"arn:aws:s3:::public-bucket/folder/object.txt"
                  }
                ]}""";

        assertFalse(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void wildcardActionAndResourceMatch() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":"*",
                  "Action":"s3:Get*",
                  "Resource":"arn:aws:s3:::public-bucket/folder/*"
                }}""";

        assertTrue(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void actionMismatchDoesNotAllow() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":"*",
                  "Action":"s3:PutObject",
                  "Resource":"arn:aws:s3:::public-bucket/*"
                }}""";

        assertFalse(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void resourceMismatchDoesNotAllow() {
        String policy = """
                {"Version":"2012-10-17","Statement":{
                  "Effect":"Allow",
                  "Principal":"*",
                  "Action":"s3:GetObject",
                  "Resource":"arn:aws:s3:::other-bucket/*"
                }}""";

        assertFalse(S3PublicAccessEvaluator.publicPolicyAllows(
                OBJECT_MAPPER, policy, "s3:GetObject", OBJECT_ARN));
    }

    @Test
    void arnHelpersBuildBucketAndObjectArns() {
        assertEquals(BUCKET_ARN, S3PublicAccessEvaluator.bucketArn(BUCKET));
        assertEquals(OBJECT_ARN, S3PublicAccessEvaluator.objectArn(BUCKET, "folder/object.txt"));
    }

    @Test
    void allUsersReadAclAllowsPublicRead() {
        String acl = """
                <AccessControlPolicy>
                  <AccessControlList>
                    <Grant>
                      <Grantee><URI>%s</URI></Grantee>
                      <Permission>READ</Permission>
                    </Grant>
                  </AccessControlList>
                </AccessControlPolicy>
                """.formatted(S3PublicAccessEvaluator.ALL_USERS_GROUP_URI);

        assertTrue(S3PublicAccessEvaluator.aclAllowsPublicRead(acl));
    }

    @Test
    void allUsersFullControlAclAllowsPublicRead() {
        String acl = """
                <AccessControlPolicy>
                  <AccessControlList>
                    <Grant>
                      <Grantee><URI>%s</URI></Grantee>
                      <Permission>FULL_CONTROL</Permission>
                    </Grant>
                  </AccessControlList>
                </AccessControlPolicy>
                """.formatted(S3PublicAccessEvaluator.ALL_USERS_GROUP_URI);

        assertTrue(S3PublicAccessEvaluator.aclAllowsPublicRead(acl));
    }

    @Test
    void allUsersWriteAclDoesNotAllowPublicRead() {
        String acl = """
                <AccessControlPolicy>
                  <AccessControlList>
                    <Grant>
                      <Grantee><URI>%s</URI></Grantee>
                      <Permission>WRITE</Permission>
                    </Grant>
                  </AccessControlList>
                </AccessControlPolicy>
                """.formatted(S3PublicAccessEvaluator.ALL_USERS_GROUP_URI);

        assertFalse(S3PublicAccessEvaluator.aclAllowsPublicRead(acl));
    }

    @Test
    void authenticatedUsersReadAclDoesNotAllowPublicRead() {
        String acl = """
                <AccessControlPolicy>
                  <AccessControlList>
                    <Grant>
                      <Grantee><URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI></Grantee>
                      <Permission>READ</Permission>
                    </Grant>
                  </AccessControlList>
                </AccessControlPolicy>
                """;

        assertFalse(S3PublicAccessEvaluator.aclAllowsPublicRead(acl));
    }
}
