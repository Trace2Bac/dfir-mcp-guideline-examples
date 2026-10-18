/* Copyright 2026 Trace2Bac contributors. Licensed under Apache-2.0.
 * Independently implemented; design references: Mulder JSONL and Camel start/end IDs.
 */
package org.sleuthkit.autopsy.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/** Selected requirements only: lifecycle and request/result audit fields. */
final class McpAuditLog {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Map<Path,Object> LOCKS = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r,"mcp-audit-wait-observer"); t.setDaemon(true); return t;
    });
    private final Path root;
    McpAuditLog(Path root) { this.root = root.toAbsolutePath().normalize(); }
    static McpAuditLog configured() { return new McpAuditLog(McpServer.dataDirectory().resolve("audit")); }
    Call newCall(String caseKey, String caseName, String tool, JsonNode args, JsonNode requestId,
            String clientId, long waitMillis) {
        return new Call(root.resolve(sha256(caseKey.getBytes(StandardCharsets.UTF_8))+".audit.jsonl"),
                caseName,tool,args,requestId,clientId,waitMillis);
    }
    final class Call {
        private final String id=UUID.randomUUID().toString();
        private final Path log;
        private final long started=System.nanoTime();
        private final ObjectNode common=JSON.createObjectNode();
        private final long waitMillis;
        private ScheduledFuture<?> deadline;
        private boolean finished;
        private String warning;
        Call(Path log,String caseName,String tool,JsonNode args,JsonNode requestId,String clientId,long waitMillis) {
            this.log=log;this.waitMillis=waitMillis;
            common.put("schemaVersion",1);common.put("origin","autopsy_http_server");
            common.put("callId",id);common.put("caseId",caseName);common.put("tool",tool);
            common.set("arguments",args.deepCopy());common.set("requestId",requestId.deepCopy());
            if(clientId!=null)common.put("clientCallId",clientId);
            common.put("startedAt",Instant.now().toString());common.putNull("endedAt");
            common.put("toolVersion","autopsy-mcp/1.0.0");
            common.put("sourceRevision",System.getProperty("autopsy.mcp.sourceRevision","unspecified"));
            common.set("evidence",JSON.valueToTree(Map.of("status","not_accessed","reason","Call not yet dispatched to an evidence-reading tool")));
            common.putNull("resultHash");common.put("resultHashAlgorithm","SHA-256");
            common.put("resultHashScope","JSON-RPC result or error, UTF-8 JSON before audit metadata");
        }
        synchronized void start() throws IOException {
            event("started","running");
            if(waitMillis>0)deadline=DEADLINES.schedule(()->{
                synchronized(Call.this) {
                    if(!finished)try { event("wait_timeout","running"); }
                    catch(IOException ex) { warning="Wait-state audit failed: "+ex.getMessage(); }
                }
            },Math.min(waitMillis,600_000),TimeUnit.MILLISECONDS);
        }
        synchronized void evidence(Map<String,Object> evidence) {common.set("evidence",JSON.valueToTree(evidence));}
        synchronized Map<String,Object> finish(String status,JsonNode value) {
            finished=true;if(deadline!=null)deadline.cancel(false);
            common.put("endedAt",Instant.now().toString());
            try {common.put("resultHash",sha256(JSON.writeValueAsBytes(value)));event("finished",status);}
            catch(IOException ex) {warning="Completion audit failed after execution: "+ex.getMessage();}
            return responseMetadata(status,warning);
        }
        Map<String,Object> responseMetadata(String status,String warning) {
            Map<String,Object> meta=new LinkedHashMap<>();meta.put("callId",id);meta.put("status",status);
            if(warning!=null)meta.put("warning",warning);return meta;
        }
        private void event(String phase,String status) throws IOException {
            ObjectNode entry=common.deepCopy();entry.put("phase",phase);entry.put("status",status);
            entry.put("timestamp",Instant.now().toString());
            entry.put("durationMillis",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started));
            if(phase.equals("wait_timeout"))entry.put("meaning","Caller wait elapsed; server work continues");
            byte[] bytes=(JSON.writeValueAsString(entry)+"\n").getBytes(StandardCharsets.UTF_8);
            synchronized(LOCKS.computeIfAbsent(log,p->new Object())) {
                Files.createDirectories(log.getParent());
                try(FileChannel channel=FileChannel.open(log,StandardOpenOption.CREATE,StandardOpenOption.WRITE,StandardOpenOption.APPEND)) {
                    ByteBuffer buffer=ByteBuffer.wrap(bytes);while(buffer.hasRemaining())channel.write(buffer);channel.force(true);
                }
            }
        }
    }
    static String sha256(byte[] bytes) {
        try {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
        catch(NoSuchAlgorithmException ex) {throw new IllegalStateException(ex);}
    }
}
