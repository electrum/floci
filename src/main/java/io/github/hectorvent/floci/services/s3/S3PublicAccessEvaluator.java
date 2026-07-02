package io.github.hectorvent.floci.services.s3;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import org.jboss.logging.Logger;

import java.util.Iterator;
import java.util.List;

final class S3PublicAccessEvaluator {

    static final String ALL_USERS_GROUP_URI = "http://acs.amazonaws.com/groups/global/AllUsers";

    private static final Logger LOG = Logger.getLogger(S3PublicAccessEvaluator.class);

    private S3PublicAccessEvaluator() {
    }

    static boolean publicPolicyAllows(ObjectMapper objectMapper, String policy, String action, String resourceArn) {
        if (policy == null || policy.isBlank()) {
            return false;
        }
        try {
            JsonNode statements = objectMapper.readTree(policy).path("Statement");
            boolean allowed = false;
            Iterable<JsonNode> iterable = statements.isArray() ? statements : List.of(statements);
            for (JsonNode statement : iterable) {
                if (!hasPublicPrincipal(statement.path("Principal"))
                        || statement.hasNonNull("Condition")
                        || !nodeMatches(statement.get("Action"), action)
                        || !nodeMatches(statement.get("Resource"), resourceArn)) {
                    continue;
                }
                String effect = statement.path("Effect").asText("Allow");
                if ("Deny".equalsIgnoreCase(effect)) {
                    return false;
                }
                if ("Allow".equalsIgnoreCase(effect)) {
                    allowed = true;
                }
            }
            return allowed;
        } catch (Exception e) {
            LOG.debugv("Failed to evaluate S3 bucket policy for public access: {0}", e.getMessage());
            return false;
        }
    }

    static boolean aclAllowsPublicRead(String acl) {
        return acl != null
                && acl.contains(ALL_USERS_GROUP_URI)
                && (acl.contains("<Permission>READ</Permission>")
                        || acl.contains("<Permission>FULL_CONTROL</Permission>"));
    }

    static String bucketArn(String bucketName) {
        return "arn:aws:s3:::" + bucketName;
    }

    static String objectArn(String bucketName, String key) {
        return bucketArn(bucketName) + "/" + key;
    }

    private static boolean hasPublicPrincipal(JsonNode principal) {
        if (principal == null || principal.isMissingNode() || principal.isNull()) {
            return false;
        }
        if (principal.isTextual()) {
            return "*".equals(principal.asText());
        }
        if (principal.isArray()) {
            for (JsonNode item : principal) {
                if ("*".equals(item.asText())) {
                    return true;
                }
            }
            return false;
        }
        if (principal.isObject()) {
            Iterator<JsonNode> values = principal.elements();
            while (values.hasNext()) {
                if (nodeContainsPublicPrincipal(values.next())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean nodeContainsPublicPrincipal(JsonNode node) {
        if (node == null || node.isNull()) {
            return false;
        }
        if (node.isTextual()) {
            return "*".equals(node.asText());
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                if ("*".equals(item.asText())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean nodeMatches(JsonNode node, String value) {
        if (node == null || node.isNull()) {
            return false;
        }
        if (node.isTextual()) {
            return IamPolicyEvaluator.globMatches(node.asText(), value);
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (item.isTextual() && IamPolicyEvaluator.globMatches(item.asText(), value)) {
                    return true;
                }
            }
        }
        return false;
    }
}
