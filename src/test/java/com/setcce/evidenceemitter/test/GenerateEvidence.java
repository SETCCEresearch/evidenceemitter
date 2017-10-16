package com.setcce.evidenceemitter.test;

import com.setcce.evidenceemitter.EvidenceEmitter;
import org.apache.commons.io.FileUtils;
import org.holodeckb2b.interfaces.workerpool.TaskConfigurationException;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Created by zelicj on 13/10/2017.
 */
public class GenerateEvidence extends EvidenceEmitter {
    @Test
    public void test() {
        try {
            String tmp = UUID.randomUUID().toString();
            File sourceFile = new File("src/test/resources/received-dispatch.xml");
            File testFile = new File("src/test/resources/" + tmp + "/received-dispatch.xml");

            String sourcePath = sourceFile.getParentFile().getAbsolutePath();
            String testPath = testFile.getParentFile().getAbsolutePath();

            new File(testPath).mkdir();
            FileUtils.copyFile(sourceFile, testFile);

            Map<String, ?> parameters = new HashMap<>();
            Map<String, String> parametersStrings = (Map<String, String>) parameters;
            parametersStrings.put("outputPath", testPath);
            parametersStrings.put("watchPath", testPath);
            parametersStrings.put("keyStore", sourcePath + "/privatekeys.jks");
            parametersStrings.put("keyStorePassword", "secrets");
            parametersStrings.put("keyPairAlias", "generalerds_ap_test");

            super.setParameters(parameters);

            super.onChange(testFile, Event.ADDED);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
