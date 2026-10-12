package io.github.hectorvent.floci.services.stepfunctions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.cloudformation.CloudFormationQueryHandler;
import io.github.hectorvent.floci.services.dynamodb.DynamoDbFacade;
import io.github.hectorvent.floci.services.dynamodb.DynamoDbJsonHandler;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ecs.EcsJsonHandler;
import io.github.hectorvent.floci.services.ecs.EcsService;
import io.github.hectorvent.floci.services.eventbridge.EventBridgeHandler;
import io.github.hectorvent.floci.services.lambda.LambdaAliasStore;
import io.github.hectorvent.floci.services.lambda.LambdaExecutorService;
import io.github.hectorvent.floci.services.lambda.LambdaFunctionStore;
import io.github.hectorvent.floci.services.lambda.LambdaTargetResolver;
import io.github.hectorvent.floci.services.lambda.model.InvocationType;
import io.github.hectorvent.floci.services.lambda.model.InvokeResult;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.scheduler.SchedulerController;
import io.github.hectorvent.floci.services.scheduler.SchedulerService;
import io.github.hectorvent.floci.services.sns.SnsJsonHandler;
import io.github.hectorvent.floci.services.sqs.SqsJsonHandler;
import io.github.hectorvent.floci.services.stepfunctions.model.Execution;
import io.github.hectorvent.floci.services.stepfunctions.model.HistoryEvent;
import io.github.hectorvent.floci.services.stepfunctions.model.StateMachine;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.mutiny.core.Vertx;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A Lambda Task given a function ARN invokes the function that ARN names: the one in its own
 * account and region, never a same-named function of the state machine's. The optimized
 * integration calls Lambda's Invoke in the state machine's region, which refuses an ARN from
 * another region. Under IAM enforcement, the function runs only when {@link LambdaTaskAuthorizer}
 * lets the execution role invoke it.
 */
@QuarkusTest
class AslExecutorLambdaArnTargetTest {

    private static final String REGION = "us-east-2";
    private static final String OTHER_REGION = "eu-west-1";
    private static final String ACCOUNT = "000000000000";
    private static final String OTHER_ACCOUNT = "111111111111";
    private static final String FUNCTION_NAME = "worker";
    private static final String ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/test-role";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private LambdaExecutorService lambdaExecutor;
    private LambdaFunctionStore functionStore;
    private AslExecutor executor;

    @Inject
    Vertx vertx;

    @BeforeEach
    void setUp() throws Exception {
        lambdaExecutor = mock(LambdaExecutorService.class);
        functionStore = mock(LambdaFunctionStore.class);
        LambdaFunction home = function(ACCOUNT, REGION);
        LambdaFunction otherRegion = function(ACCOUNT, OTHER_REGION);
        LambdaFunction otherAccount = function(OTHER_ACCOUNT, REGION);
        when(functionStore.get(REGION, FUNCTION_NAME)).thenReturn(Optional.of(home));
        when(functionStore.get(OTHER_REGION, FUNCTION_NAME)).thenReturn(Optional.of(otherRegion));
        when(functionStore.getForAccount(OTHER_ACCOUNT, REGION, FUNCTION_NAME)).thenReturn(Optional.of(otherAccount));
        for (LambdaFunction function : List.of(home, otherRegion, otherAccount)) {
            byte[] output = objectMapper.writeValueAsBytes(
                    objectMapper.createObjectNode().put("invoked", function.getFunctionArn()));
            when(lambdaExecutor.invoke(eq(function), any(byte[].class), eq(InvocationType.RequestResponse)))
                    .thenReturn(new InvokeResult(200, null, output, null, "request"));
        }

        executor = newExecutor(mock(EmulatorConfig.class), null);
    }

    private AslExecutor newExecutor(EmulatorConfig config, LambdaTaskAuthorizer authorizer) {
        return new AslExecutor(
                lambdaExecutor,
                new LambdaTargetResolver(functionStore, mock(LambdaAliasStore.class)),
                mock(DynamoDbFacade.class),
                mock(DynamoDbJsonHandler.class),
                mock(SqsJsonHandler.class), mock(SnsJsonHandler.class),
                mock(CloudFormationQueryHandler.class),
                mock(Ec2Service.class),
                mock(S3Service.class),
                mock(EcsService.class),
                mock(EcsJsonHandler.class),
                mock(EventBridgeHandler.class),
                mock(SchedulerService.class),
                mock(SchedulerController.class),
                null,
                objectMapper,
                new JsonataEvaluator(objectMapper),
                mock(Instance.class), config, vertx, null, null, null, authorizer);
    }

    private static LambdaFunction function(String account, String region) {
        LambdaFunction function = new LambdaFunction();
        function.setFunctionName(FUNCTION_NAME);
        function.setFunctionArn(functionArn(account, region));
        return function;
    }

    private static String functionArn(String account, String region) {
        return "arn:aws:lambda:%s:%s:function:%s".formatted(region, account, FUNCTION_NAME);
    }

    @Test
    void aFunctionArnResourceInvokesTheFunctionInItsOwnRegion() throws Exception {
        Execution execution = run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task", "Resource": "%s", "End": true}}}
                """.formatted(functionArn(ACCOUNT, OTHER_REGION)));

        assertEquals("SUCCEEDED", execution.getStatus());
        assertEquals(functionArn(ACCOUNT, OTHER_REGION),
                objectMapper.readTree(execution.getOutput()).path("invoked").asText());
    }

    @Test
    void aFunctionArnInAnotherAccountInvokesThatAccountsFunction() throws Exception {
        Execution execution = run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task",
                  "Resource": "arn:aws:states:::lambda:invoke",
                  "Parameters": {"FunctionName": "%s"}, "End": true}}}
                """.formatted(functionArn(OTHER_ACCOUNT, REGION)));

        assertEquals("SUCCEEDED", execution.getStatus());
        JsonNode output = objectMapper.readTree(execution.getOutput());
        assertEquals(functionArn(OTHER_ACCOUNT, REGION), output.path("Payload").path("invoked").asText());
    }

    @Test
    void optimizedInvokeRefusesAFunctionArnFromAnotherRegion() {
        Execution execution = run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task",
                  "Resource": "arn:aws:states:::lambda:invoke",
                  "Parameters": {"FunctionName": "%s"}, "End": true}}}
                """.formatted(functionArn(ACCOUNT, OTHER_REGION)));

        assertEquals("FAILED", execution.getStatus());
        assertEquals("Lambda.InvalidParameterValueException", execution.getError());
    }

    @Test
    void underIamEnforcementAFunctionInAnotherAccountRunsWhenItsPolicyAndTheRolesAllowIt() throws Exception {
        LambdaTaskAuthorizer authorizer = enforcing();
        when(authorizer.refusal(ROLE_ARN, functionArn(OTHER_ACCOUNT, REGION))).thenReturn(Optional.empty());

        Execution execution = run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task", "Resource": "%s", "End": true}}}
                """.formatted(functionArn(OTHER_ACCOUNT, REGION)));

        assertEquals("SUCCEEDED", execution.getStatus());
        assertEquals(functionArn(OTHER_ACCOUNT, REGION),
                objectMapper.readTree(execution.getOutput()).path("invoked").asText());
    }

    @Test
    void underIamEnforcementAFunctionInAnotherAccountIsRefusedWithTheAuthorizersReason() {
        LambdaTaskAuthorizer authorizer = enforcing();
        when(authorizer.refusal(ROLE_ARN, functionArn(OTHER_ACCOUNT, REGION))).thenReturn(Optional.of("refused"));

        Execution execution = run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task", "Resource": "%s", "End": true}}}
                """.formatted(functionArn(OTHER_ACCOUNT, REGION)));

        assertEquals("FAILED", execution.getStatus());
        assertEquals("Lambda.AccessDeniedException", execution.getError());
        assertEquals("refused", execution.getCause());
        verify(lambdaExecutor, never()).invoke(any(), any(byte[].class), any());
    }

    @Test
    void underIamEnforcementTheFunctionIsAuthorizedAsTheTaskNamesIt() {
        LambdaTaskAuthorizer authorizer = enforcing();
        when(authorizer.refusal(anyString(), anyString())).thenReturn(Optional.of("refused"));

        run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task",
                  "Resource": "arn:aws:states:::lambda:invoke",
                  "Parameters": {"FunctionName": "%s:function:%s:live"}, "End": true}}}
                """.formatted(OTHER_ACCOUNT, FUNCTION_NAME));

        verify(authorizer).refusal(ROLE_ARN, functionArn(OTHER_ACCOUNT, REGION) + ":live");
    }

    @Test
    void underIamEnforcementAFullFunctionArnIsAuthorizedAsItIsWritten() {
        LambdaTaskAuthorizer authorizer = enforcing();
        when(authorizer.refusal(anyString(), anyString())).thenReturn(Optional.of("refused"));
        String chinaFunction = "arn:aws-cn:lambda:cn-north-1:%s:function:%s:7".formatted(OTHER_ACCOUNT, FUNCTION_NAME);

        run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task", "Resource": "%s", "End": true}}}
                """.formatted(chinaFunction));

        verify(authorizer).refusal(ROLE_ARN, chinaFunction);
    }

    @Test
    void underIamEnforcementAFunctionInTheStateMachinesAccountIsAuthorizedToo() {
        LambdaTaskAuthorizer authorizer = enforcing();
        when(authorizer.refusal(ROLE_ARN, functionArn(ACCOUNT, REGION))).thenReturn(Optional.of("refused"));

        Execution execution = run("""
                {"StartAt": "Call", "States": {"Call": {"Type": "Task",
                  "Resource": "arn:aws:states:::lambda:invoke",
                  "Parameters": {"FunctionName": "%s"}, "End": true}}}
                """.formatted(FUNCTION_NAME));

        assertEquals("FAILED", execution.getStatus());
        assertEquals("Lambda.AccessDeniedException", execution.getError());
        verify(lambdaExecutor, never()).invoke(any(), any(byte[].class), any());
    }

    private LambdaTaskAuthorizer enforcing() {
        EmulatorConfig enforcing = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(enforcing.services().iam().enforcementEnabled()).thenReturn(true);
        LambdaTaskAuthorizer authorizer = mock(LambdaTaskAuthorizer.class);
        executor = newExecutor(enforcing, authorizer);
        return authorizer;
    }

    private Execution run(String definition) {
        StateMachine stateMachine = new StateMachine();
        stateMachine.setName("lambda-arn-target");
        stateMachine.setStateMachineArn(
                "arn:aws:states:%s:%s:stateMachine:lambda-arn-target".formatted(REGION, ACCOUNT));
        stateMachine.setRoleArn(ROLE_ARN);
        stateMachine.setDefinition(definition);

        Execution execution = new Execution();
        execution.setName("lambda-arn-target-execution");
        execution.setExecutionArn("arn:aws:states:%s:%s:execution:lambda-arn-target:run-1"
                .formatted(REGION, ACCOUNT));
        execution.setStateMachineArn(stateMachine.getStateMachineArn());
        execution.setInput("{}");

        List<HistoryEvent> history = new ArrayList<>();
        executor.executeSync(stateMachine, execution, history, (updated, events) -> {
        });
        return execution;
    }
}
