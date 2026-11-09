package com.alinksec.bootstrap;
/** Explicit live-principal fixture for route tests; real sessions have separate DB tests. */
public final class TestJwt {
    private static final java.util.Map<String,com.alinksec.service.user.UserService.UserProfile> sessions=new java.util.concurrent.ConcurrentHashMap<>();
    public static com.alinksec.gateway.rest.JwtAuthInterceptor interceptor(com.alinksec.gateway.rest.JwtSecretHolder holder){
        var users=org.mockito.Mockito.mock(com.alinksec.service.user.UserService.class);
        org.mockito.Mockito.when(users.authenticate(org.mockito.ArgumentMatchers.anyLong(),org.mockito.ArgumentMatchers.anyString())).thenAnswer(i->{
            var profile=sessions.get(i.getArgument(1));
            if(profile==null || profile.id()!=((Long)i.getArgument(0)).longValue())throw new IllegalArgumentException("unknown test session");
            return profile;
        });
        return new com.alinksec.gateway.rest.JwtAuthInterceptor(holder,users);
    }
    public static String token(String secret,java.util.Map<String,Object> claims,long ttl){
        String sid=java.util.UUID.randomUUID().toString();var copy=new java.util.HashMap<>(claims);copy.put("sid",sid);
        sessions.put(sid,new com.alinksec.service.user.UserService.UserProfile(((Number)claims.get("uid")).longValue(),String.valueOf(claims.get("username")),"test",String.valueOf(claims.get("role")),"",0));
        return com.alinksec.common.util.JwtUtil.sign(secret,copy,ttl);
    }
}
