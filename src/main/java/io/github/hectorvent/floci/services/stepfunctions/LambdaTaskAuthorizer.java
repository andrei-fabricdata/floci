package io.github.hectorvent.floci.services.stepfunctions;

import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.IamConditionContextResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.ResourceAccountRelationship;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.ResourcePolicyDecision;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.SimulationDecision;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.RequestPrincipal;
import io.github.hectorvent.floci.services.iam.ResourcePolicyProvider.ResourcePolicy;
import io.github.hectorvent.floci.services.iam.ScpProvider;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.lambda.LambdaResourcePolicyProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Decides a Lambda Task's call to its function. Without {@code Credentials}, the task calls Invoke as
 * the state machine's execution role (Step Functions Developer Guide, "I can't invoke a Lambda
 * function from another account": the role "must have the right permissions to invoke
 * cross-account Lambda functions"). Within one account, the role's policies or the function's policy
 * can allow the call; across accounts, both have to (IAM User Guide, cross-account policy evaluation
 * logic). The role's permissions boundary and its account's service control policies limit it, and
 * an explicit Deny in any of them refuses it.
 */
@ApplicationScoped
public class LambdaTaskAuthorizer {

    private static final Logger LOG = Logger.getLogger(LambdaTaskAuthorizer.class);
    private static final String ACTION = "lambda:InvokeFunction";

    private final IamService iamService;
    private final IamPolicyEvaluator evaluator;
    private final LambdaResourcePolicyProvider functionPolicies;
    private final Instance<ScpProvider> scpProvider;

    @Inject
    public LambdaTaskAuthorizer(IamService iamService, IamPolicyEvaluator evaluator,
                                LambdaResourcePolicyProvider functionPolicies, Instance<ScpProvider> scpProvider) {
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.functionPolicies = functionPolicies;
        this.scpProvider = scpProvider;
    }

    /**
     * Returns why {@code roleArn} may not invoke {@code functionArn}, as Lambda's access denied
     * message words it, or nothing when it may.
     *
     * @param functionArn the function, version or alias the task invokes, qualified as it names it
     */
    public Optional<String> refusal(String roleArn, String functionArn) {
        AwsArnUtils.Arn function = AwsArnUtils.parse(functionArn);
        Optional<IamRole> executionRole = executionRole(roleArn);
        if (executionRole.isEmpty()) {
            LOG.infov("Execution role {0} names no existing role, so it cannot invoke {1}", roleArn, functionArn);
            return Optional.of(denied(roleArn, functionArn, "because no identity-based policy allows the "
                    + ACTION + " action"));
        }
        // The role is evaluated as itself, under the ARN IAM holds for it, whichever form names it.
        String executionRoleArn = executionRole.get().getArn();
        CallerContext role = iamService.resolvePrincipalContext(executionRoleArn);
        AwsArnUtils.Arn roleId = AwsArnUtils.parse(executionRoleArn);
        List<List<String>> scpLevels = scpProvider.isResolvable()
                ? scpProvider.get().effectiveScpLevels(roleId.accountId()) : null;

        List<ResourcePolicy> policies = functionPolicies.getResourcePolicies("lambda", functionArn);
        String ownerAccount = policies.isEmpty() ? function.accountId() : policies.getFirst().ownerAccountId();
        List<String> documents = policies.stream()
                .map(ResourcePolicy::policyDocument)
                .filter(document -> document != null && !document.isBlank())
                .toList();
        Map<String, List<String>> context = IamConditionContextResolver.withGlobalContext(
                Map.of("aws:PrincipalArn", List.of(executionRoleArn)), functionArn, function.region(),
                roleId.accountId(), ownerAccount);

        RequestPrincipal session = RequestPrincipal.roleSession(sessionArn(executionRoleArn), executionRoleArn);
        ResourcePolicyDecision functionPolicy = evaluator.evaluateResourcePolicyFor(
                documents.isEmpty() ? null : documents, session, ACTION, functionArn, context);
        ResourceAccountRelationship relationship = roleId.accountId().equals(ownerAccount)
                ? ResourceAccountRelationship.SAME_ACCOUNT : ResourceAccountRelationship.CROSS_ACCOUNT;
        Decision decision = evaluator.evaluateResolvedResourcePolicy(
                role.withScpLevels(scpLevels), functionPolicy, relationship, ACTION, functionArn, context);
        if (decision == Decision.ALLOW) {
            return Optional.empty();
        }
        return Optional.of(denied(executionRoleArn, functionArn,
                reason(role, scpLevels, functionPolicy, relationship, functionArn, context)));
    }

    /**
     * The role {@code roleArn} names, matched as STS {@code AssumeRole} matches a role ARN
     * ({@link IamService#roleArnMatches}). A state machine's role ARN that names no role, or names
     * one under another path, is not that role, and a grant written for the ARN must not admit it.
     */
    private Optional<IamRole> executionRole(String roleArn) {
        if (!AwsArnUtils.isArn(roleArn)) {
            return Optional.empty();
        }
        AwsArnUtils.Arn arn = AwsArnUtils.parse(roleArn);
        String roleName = arn.resource().substring(arn.resource().lastIndexOf('/') + 1);
        return iamService.findRole(arn.accountId(), roleName)
                .filter(role -> IamService.roleArnMatches(roleArn, role));
    }

    /**
     * The context that ends the access denied message (IAM User Guide, "Access denied error message
     * examples"): the first policy type that refuses the call, explicit denials before implicit ones,
     * each in the order AWS evaluates the types: service control policies, the resource-based policy,
     * identity-based policies, then the permissions boundary.
     */
    private String reason(CallerContext role, List<List<String>> scpLevels, ResourcePolicyDecision functionPolicy,
                          ResourceAccountRelationship relationship, String functionArn,
                          Map<String, List<String>> context) {
        List<SimulationDecision> scps = scpLevels == null ? List.of() : scpLevels.stream()
                .filter(level -> !level.isEmpty())
                .map(level -> simulate(level, functionArn, context))
                .toList();
        SimulationDecision identity = simulate(role.identityPolicies(), functionArn, context);
        SimulationDecision boundary = role.boundaryPolicyDocument() == null
                ? SimulationDecision.ALLOWED
                : simulate(List.of(role.boundaryPolicyDocument()), functionArn, context);
        boolean functionAllows = functionPolicy == ResourcePolicyDecision.ALLOW
                || functionPolicy == ResourcePolicyDecision.ALLOW_DIRECT_IAM_USER;

        if (scps.contains(SimulationDecision.EXPLICIT_DENY)) {
            return "with an explicit deny in a service control policy";
        }
        if (functionPolicy == ResourcePolicyDecision.EXPLICIT_DENY) {
            return "with an explicit deny in a resource-based policy";
        }
        if (identity == SimulationDecision.EXPLICIT_DENY) {
            return "with an explicit deny in an identity-based policy";
        }
        if (boundary == SimulationDecision.EXPLICIT_DENY) {
            return "with an explicit deny in a permissions boundary";
        }
        if (scps.contains(SimulationDecision.IMPLICIT_DENY)) {
            return "because no service control policy allows the " + ACTION + " action";
        }
        if (relationship == ResourceAccountRelationship.CROSS_ACCOUNT && !functionAllows) {
            return "because no resource-based policy allows the " + ACTION + " action";
        }
        if (identity != SimulationDecision.ALLOWED
                && (relationship == ResourceAccountRelationship.CROSS_ACCOUNT || !functionAllows)) {
            return "because no identity-based policy allows the " + ACTION + " action";
        }
        return "because no permissions boundary allows the " + ACTION + " action";
    }

    private SimulationDecision simulate(List<String> documents, String functionArn, Map<String, List<String>> context) {
        return evaluator.simulatePrincipalPolicy(CallerContext.of(documents), ACTION, functionArn, context);
    }

    private static String denied(String roleArn, String functionArn, String reason) {
        return "User: " + sessionArn(roleArn) + " is not authorized to perform: " + ACTION + " on resource: "
                + functionArn + " " + reason;
    }

    /**
     * The role's session, which makes the call, as the Step Functions Developer Guide writes it in
     * an access denied message: {@code arn:aws:sts::account-id:assumed-role/StepFunctions-MyStateMachine-role}.
     */
    private static String sessionArn(String roleArn) {
        try {
            AwsArnUtils.Arn role = AwsArnUtils.parse(roleArn);
            String roleName = role.resource().substring(role.resource().lastIndexOf('/') + 1);
            return AwsArnUtils.Arn.global(role.partition(), "sts", role.accountId(), "assumed-role/" + roleName)
                    .toString();
        } catch (IllegalArgumentException ignored) {
            // A role ARN that does not parse names no session, so the message names the ARN as given.
            return roleArn;
        }
    }
}
