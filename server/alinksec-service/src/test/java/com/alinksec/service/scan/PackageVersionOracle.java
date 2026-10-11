package com.alinksec.service.scan;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/** CI entry point: consume independently generated native comparisons without a test-framework runtime. */
public final class PackageVersionOracle {
    public static void main(String[] args) throws Exception {
        boolean dpkgOnly = args.length == 1 && "dpkg".equals(args[0]);
        if (args.length != 0 && !dpkgOnly) throw new IllegalArgumentException("Unknown native validation mode");
        int rpm = 0, dpkg = 0;
        try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null) {
                String[] fields = line.split("\t", -1);
                if (fields.length != 4 || line.length() > 1024) throw new IllegalArgumentException("Invalid native comparison record");
                int expected = Integer.parseInt(fields[3]);
                int actual = Integer.signum(PackageVersions.compare(fields[0], fields[1], fields[2]));
                if (actual != expected) throw new AssertionError("Native ordering differs: " + line + " actual=" + actual);
                if ("rpm".equals(fields[0])) rpm++;
                else if ("dpkg".equals(fields[0])) dpkg++;
                else throw new IllegalArgumentException("Unknown native source");
            }
        }
        if (dpkg == 0 || (dpkgOnly ? rpm != 0 : rpm == 0)) throw new AssertionError("Required native comparators are missing");
        System.out.printf("Native package versions: rpm_comparisons=%d dpkg_comparisons=%d all_pairs=true package_installs=0%n", rpm, dpkg);
    }
}
