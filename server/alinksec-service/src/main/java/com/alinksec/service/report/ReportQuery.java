package com.alinksec.service.report;

import java.time.*;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;

/** Natural-day selection is independent of browser and database session timezones. */
public record ReportQuery(String from, String to, Long groupId, Integer osType) {
    public static final ZoneId ZONE=ZoneId.of("Asia/Shanghai");
    public ReportQuery checked(Instant now) {
        LocalDate today=now.atZone(ZONE).toLocalDate(),end=date(to,today),start=date(from,end.minusDays(29));
        if(start.isBefore(LocalDate.of(1970,1,1)) || start.isAfter(end) || end.isAfter(today) || ChronoUnit.DAYS.between(start,end)>=366
                || groupId!=null && groupId<=0 || osType!=null && osType!=1 && osType!=2)
            throw new IllegalArgumentException("报表日期须为不超过今天的连续 1 至 366 天，分组和系统须有效");
        return new ReportQuery(start.toString(),end.toString(),groupId,osType);
    }
    private static LocalDate date(String value,LocalDate fallback) {
        if(value==null || value.isBlank())return fallback;
        if(!value.matches("\\d{4}-\\d{2}-\\d{2}"))throw new IllegalArgumentException("日期须为 YYYY-MM-DD");
        try{return LocalDate.parse(value);}catch(DateTimeParseException e){throw new IllegalArgumentException("报表日期无效");}
    }
    public Instant start(){return LocalDate.parse(from).atStartOfDay(ZONE).toInstant();}
    public Instant endExclusive(){return LocalDate.parse(to).plusDays(1).atStartOfDay(ZONE).toInstant();}
}
