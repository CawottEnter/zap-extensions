package org.zaproxy.zap.extension.recordsattack.refound;

import org.apache.log4j.Logger;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class PersistentXSSAttack {
    /** Prefix for internationalised messages used by this rule */

    private static final String MESSAGE_PREFIX = "ascanrules.testpersistentxssattack.";


    private static final String GENERIC_SCRIPT_ALERT = "<script>alert(1);</script>";
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private static Logger log = Logger.getLogger(PersistentXSSAttack.class);
}
