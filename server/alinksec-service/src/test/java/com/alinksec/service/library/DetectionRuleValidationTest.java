package com.alinksec.service.library;
import com.alinksec.common.util.JsonUtils;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
class DetectionRuleValidationTest {
    @Test void publisherRejectsRangesAndTypesThatAgentCannotInstall() {
        var good=JsonUtils.read("{\"name\":\"Harmless.Rule\",\"strings\":[{\"value\":\"needle\"}]}");
        SignaturePackage.validateRule(good);
        for(String field:List.of("severity","max_mb")) {
            var bad=(com.fasterxml.jackson.databind.node.ObjectNode)good.deepCopy();
            bad.put(field,4294967300L); assertThrows(IllegalArgumentException.class,()->SignaturePackage.validateRule(bad));
            bad.put(field,"4"); assertThrows(IllegalArgumentException.class,()->SignaturePackage.validateRule(bad));
        }
        var many=(com.fasterxml.jackson.databind.node.ObjectNode)good.deepCopy();var array=many.putArray("strings");
        for(int i=0;i<65;i++) array.addObject().put("value","x");
        assertThrows(IllegalArgumentException.class,()->SignaturePackage.validateRule(many));
        var large=(com.fasterxml.jackson.databind.node.ObjectNode)good.deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode)large.path("strings").get(0)).put("value","x".repeat(1025));
        assertThrows(IllegalArgumentException.class,()->SignaturePackage.validateRule(large));
        var ext=(com.fasterxml.jackson.databind.node.ObjectNode)good.deepCopy();ext.putArray("exts").add("."+"扩".repeat(11));
        assertThrows(IllegalArgumentException.class,()->SignaturePackage.validateRule(ext));
    }
}
