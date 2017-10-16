package com.setcce.evidenceemitter.test;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

/**
 * Created by zelicj on 13/10/2017.
 */
public class TestRunner {
    public static void main(String[] args) {
        Result result = JUnitCore.runClasses(
                GenerateEvidence.class
        );
        for (Failure failure : result.getFailures()) {
            System.out.println(failure.toString());
        }
        System.out.println(result.wasSuccessful());
    }
}
