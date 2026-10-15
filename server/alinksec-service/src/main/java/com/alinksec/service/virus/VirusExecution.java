package com.alinksec.service.virus;

import org.springframework.jdbc.core.JdbcTemplate;
import java.util.Locale;

/** Shared database lock orders task acceptance, delivery, action and policy changes. */
final class VirusExecution {
    private VirusExecution() {}
    static void lock(JdbcTemplate jdbc) { jdbc.update("UPDATE t_virus_state SET revision=revision WHERE id=1"); }
    static void actor(JdbcTemplate jdbc,Long id) {
        if(id==null || jdbc.update("UPDATE t_user SET status=status WHERE id=? AND status=1",id)!=1
                || jdbc.queryForObject("SELECT count(*) FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND r.name IN ('admin','operator')",Integer.class,id)!=1)
            throw new IllegalArgumentException("检测操作须由当前有效管理员或运维账号执行");
    }
    static String path(String value) {
        if(value==null || value.isBlank() || value.length()>512 || value.indexOf('\0')>=0 || value.contains("\n") || value.contains("\r")) throw new IllegalArgumentException("路径无效或超过512字符");
        boolean windows=value.matches("^[A-Za-z]:[\\\\/].*");
        if(!value.startsWith("/") && !windows) throw new IllegalArgumentException("扫描与白名单须使用绝对路径，Windows仅支持本地盘符");
        String normalized=windows?value.replace('\\','/'):value;
        if(windows && normalized.substring(2).contains(":")) throw new IllegalArgumentException("不支持 Windows 替代数据流路径");
        for(String component:normalized.split("/")) if(component.equals(".") || component.equals("..")) throw new IllegalArgumentException("路径不能包含 . 或 ..");
        return value;
    }
    static String hash(String value) {
        if(value==null || !value.matches("(?i)[0-9a-f]{64}")) throw new IllegalArgumentException("需要检出时的SHA256摘要");
        return value.toLowerCase(Locale.ROOT);
    }
}
