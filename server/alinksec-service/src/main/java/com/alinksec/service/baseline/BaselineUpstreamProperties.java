package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.library.FeedDownload;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import java.net.URI;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/** Static allowlist: the web API cannot add URLs, signing keys or package scopes. */
@Component
@ConfigurationProperties(prefix="alinksec.baseline-upstream")
public class BaselineUpstreamProperties {
    private List<Source> sources=new ArrayList<>();
    private long maxArtifactBytes=64L<<20;
    public List<Source> getSources(){return sources;}
    public void setSources(List<Source> value){sources=value;}
    public long getMaxArtifactBytes(){return Math.max(2L<<20,Math.min(maxArtifactBytes,256L<<20));}
    public void setMaxArtifactBytes(long value){maxArtifactBytes=value;}
    public static class Source {
        private String id="",name="",url="",publicKey="";
        private boolean enabled;
        private long intervalMs=3_600_000;
        private List<String> scopes=new ArrayList<>();
        public String getId(){return id;} public void setId(String v){id=v;}
        public String getName(){return name;} public void setName(String v){name=v;}
        public String getUrl(){return url;} public void setUrl(String v){url=v;}
        public String getPublicKey(){return publicKey;} public void setPublicKey(String v){publicKey=v;}
        public boolean isEnabled(){return enabled;} public void setEnabled(boolean v){enabled=v;}
        public long getIntervalMs(){return intervalMs;} public void setIntervalMs(long v){intervalMs=v;}
        public List<String> getScopes(){return scopes;} public void setScopes(List<String> v){scopes=v;}
        public PublicKey key(){try{return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));}
            catch(Exception e){throw new IllegalArgumentException("上游 Ed25519 公钥无效");}}
        public String keyHash(){return ScapPackage.digest(key().getEncoded());}
        public String fingerprint(){return ScapStore.digest(JsonUtils.write(List.of(url,keyHash(),new TreeSet<>(scopes))));}
        public URI address(){URI uri=FeedDownload.validateAddress(url);if(uri.getQuery()!=null)throw new IllegalArgumentException("上游地址不得包含查询参数");return uri;}
        public void validate(){
            if(!id.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")||name.isBlank()||name.length()>128)throw new IllegalArgumentException("上游编号或名称无效");
            address();key();interval(intervalMs);
            if(scopes.isEmpty()||scopes.size()>64||new HashSet<>(scopes).size()!=scopes.size()||scopes.stream().anyMatch(s->!s.matches("(baseline|scap):[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")))throw new IllegalArgumentException("上游需配置唯一的包类型和编号范围");
        }
    }
    public static void interval(long value){if(value<3_600_000||value>604_800_000)throw new IllegalArgumentException("更新间隔应为 1 小时至 7 天");}
}
