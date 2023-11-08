package com.salesforce.ast;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.io.File;
import java.util.*;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.salesforce.ast.oss.snykci.pojo.*;
import com.salesforce.ast.sast.scm.git.GitSomaManager;
import com.salesforce.ast.oss.cs.reports.ReportUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.salesforce.ast.config.MasterConfig;
import com.salesforce.ast.oss.Util;
import com.salesforce.ast.oss.metrics.OSSMetricsManager;
import com.salesforce.ast.oss.snykci.dao.SnykFailuresDAO;
import com.salesforce.ast.oss.snykci.dao.SnykOrgMappingsDAO;
import com.salesforce.ast.oss.snykci.git.AstSnykCIGit;
import com.salesforce.ast.oss.snykci.snyk.AstSnyk;
import com.salesforce.ast.s3.S3Store;
import com.salesforce.ast.util.PasswordManager;
import com.salesforce.sds.core.script.ScriptExecutor;


public class SnykIntegrationManagerTest {

	@Test
	public void testOnboardUser1() throws Exception {
		String s = "[{\n" +
				"\"id\": \"0ff64d0a-d8ad-4717-b37d-26da1ffc3bf5\",\n" +
				"\"name\": \"GITSOMA/GRC-Operation\",\n" +
				"\"slug\": \"gitsomagrc-operation\",\n" +
				"\"awsKey\": \"SFDC_AWS_EXAMPLE_KEY\",\n" +
				"\"group\": {\n" +
				"\"name\": \"SFDC\",\n" +
				"\"id\": \"6778547c-2c44-4b9b-81a4-a14c47b55302\"\n" +
				"}\n" +
				"}]";

		ObjectMapper mapper = new ObjectMapper();
		mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		JsonNode node1 = mapper.readTree(s);
		ArrayNode a =  (ArrayNode) node1;
		when(astSnyk.getOrgs(anyString())).thenReturn(a);
		when(gitSomaManager.getFileContentAsString(anyString(),anyString(),anyString())).thenReturn("[\n" +
				"  {\n" +
				"    \"email\": \"praveen.tripathi@salesforce.com\",\n" +
				"    \"snykGroup\": \"SFDC\",\n" +
				"    \"snykOrg\": \"GITSOMA/Infrastructure Security\",\n" +
				"    \"gitOrg\": \"Infrastructure Security\"\n" +
				"  },\n" +
				"  {\n" +
				"    \"email\": \"akshay.kumar1@salesforce.com\",\n" +
				"    \"snykGroup\": \"SFDC\",\n" +
				"    \"snykOrg\": \"GITSOMA/Infrastructure Security\",\n" +
				"    \"gitOrg\": \"Infrastructure Security\"\n" +
				"  }\n" +
				"]");
		when(gitSomaManager.writeFile(anyString(),anyString(),anyString(),anyString(),anyString())).thenThrow(new RuntimeException());
		boolean b = snykCiIntegrationManager.onBoardUser();
	}
}
