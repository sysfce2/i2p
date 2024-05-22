/* I2PTunnel is GPL'ed (with the exception mentioned in I2PTunnel.java)
 * (c) 2003 - 2004 mihi
 */
package net.i2p.i2ptunnel;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import net.i2p.I2PAppContext;
import net.i2p.I2PException;
import net.i2p.app.ClientApp;
import net.i2p.app.ClientAppManager;
import net.i2p.app.Outproxy;
import net.i2p.client.I2PSession;
import net.i2p.client.LookupResult;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketOptions;
import net.i2p.crypto.Blinding;
import net.i2p.crypto.SHA256Generator;
import net.i2p.data.Base32;
import net.i2p.data.Base64;
import net.i2p.data.BlindData;
import net.i2p.data.DataHelper;
import net.i2p.data.Destination;
import net.i2p.data.Hash;
import net.i2p.i2ptunnel.localServer.LocalHTTPServer;
import net.i2p.i2ptunnel.util.HTTPRequestReader;
import net.i2p.i2ptunnel.util.InputReader;
import net.i2p.util.ConvertToHash;
import net.i2p.util.DNSOverHTTPS;
import net.i2p.util.EventDispatcher;
import net.i2p.util.InternalSocket;
import net.i2p.util.Log;
import net.i2p.util.PortMapper;

/**
 * Act as a multiplexer of I2PTunnelHTTPClients with different ports on a
 * single port. Dynamically creates a new I2PTunnelHTTPClient on a per-host
 * basis. For each new host, it creates a new I2PTunnelHTTPClient. Each
 * I2PTunnelHTTPClient is used for requests from a single specific origin.
 *
 */
public class I2PTunnelHTTPBrowserClient extends I2PTunnelHTTPClient {
    HashMap<Destination, I2PTunnelHTTPClient> clients = new HashMap<Destination, I2PTunnelHTTPClient>();
    private InternalSocketRunner isr;
    private static final boolean DEFAULT_KEEPALIVE_BROWSER = true;

    /**
     *
     */
    public I2PTunnelHTTPBrowserClient(int localPort, Logging l,
            I2PSocketManager sockMgr, I2PTunnel tunnel,
            EventDispatcher notifyThis, long clientId) {
        super(localPort, l, sockMgr, tunnel, notifyThis, clientId);
        setName("HTTP Proxy on " + tunnel.listenHost + ':' + localPort);
        notifyEvent("openHTTPClientResult", "ok");
    }

    /**
     *
     */
    public I2PTunnelHTTPBrowserClient(int localPort, Logging l, boolean ownDest,
            String wwwProxy, EventDispatcher notifyThis,
            I2PTunnel tunnel)
            throws IllegalArgumentException {
        super(localPort, l, ownDest, wwwProxy, notifyThis, tunnel);
        setName("HTTP Proxy on " + tunnel.listenHost + ':' + localPort);
        notifyEvent("openHTTPClientResult", "ok");
    }

    /**
     * Create the default options (using the default timeout, etc).
     * Warning, this does not make a copy of I2PTunnel's client options,
     * it modifies them directly.
     * unused?
     *
     * This will throw IAE on tunnel build failure
     */
    @Override
    protected I2PSocketOptions getDefaultOptions() {
        Properties defaultOpts = getTunnel().getClientOptions();
        if (!defaultOpts.contains(I2PSocketOptions.PROP_READ_TIMEOUT)) {
            defaultOpts.setProperty(I2PSocketOptions.PROP_READ_TIMEOUT,
                    "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        }
        // if (!defaultOpts.contains("i2p.streaming.inactivityTimeout"))
        // defaultOpts.setProperty("i2p.streaming.inactivityTimeout",
        // ""+DEFAULT_READ_TIMEOUT);
        // delayed start
        verifySocketManager();
        I2PSocketOptions opts = sockMgr.buildOptions(defaultOpts);
        if (!defaultOpts.containsKey(I2PSocketOptions.PROP_CONNECT_TIMEOUT)) {
            opts.setConnectTimeout(DEFAULT_CONNECT_TIMEOUT);
        }
        return opts;
    }

    /**
     * Create the default options (using the default timeout, etc).
     * Warning, this does not make a copy of I2PTunnel's client options,
     * it modifies them directly.
     * Do not use overrides for per-socket options.
     *
     * This will throw IAE on tunnel build failure
     */
    @Override
    protected I2PSocketOptions getDefaultOptions(Properties overrides) {
        Properties defaultOpts = getTunnel().getClientOptions();
        defaultOpts.putAll(overrides);
        if (!defaultOpts.contains(I2PSocketOptions.PROP_READ_TIMEOUT)) {
            defaultOpts.setProperty(I2PSocketOptions.PROP_READ_TIMEOUT,
                    "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        }
        if (!defaultOpts.contains("i2p.streaming.inactivityTimeout")) {
            defaultOpts.setProperty("i2p.streaming.inactivityTimeout",
                    "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        }
        // delayed start
        verifySocketManager();
        I2PSocketOptions opts = sockMgr.buildOptions(defaultOpts);
        if (!defaultOpts.containsKey(I2PSocketOptions.PROP_CONNECT_TIMEOUT)) {
            opts.setConnectTimeout(DEFAULT_CONNECT_TIMEOUT);
        }
        return opts;
    }

    /**
     * Actually start working on incoming connections.
     * Overridden to start an internal socket too.
     *
     */
    @Override
    public void startRunning() {
        initialize();
        if (open) {
            this.isr = new InternalSocketRunner(this);
            this.isr.start();
            int port = getLocalPort();
            _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED,
                    getTunnel().listenHost, port);
            _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED,
                    getTunnel().listenHost, port);
        }
    }

    /**
     * Overridden to close internal socket too.
     */
    @Override
    public boolean close(boolean forced) {
        int port = getLocalPort();
        int reg = _context.portMapper().getPort(PortMapper.SVC_HTTP_PROXY_TABBED);
        if (reg == port) {
            _context.portMapper().unregister(PortMapper.SVC_HTTP_PROXY_TABBED);
        }
        reg = _context.portMapper().getPort(PortMapper.SVC_HTTPS_PROXY_TABBED);
        if (reg == port) {
            _context.portMapper().unregister(PortMapper.SVC_HTTPS_PROXY_TABBED);
        }
        boolean rv = super.close(forced);
        if (this.isr != null) {
            this.isr.stopRunning();
        }
        return rv;
    }

    private void mapPort(String hostname, int port) {
        _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED + "@" +
                hostname,
                getTunnel().listenHost, port);
        _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" +
                hostname,
                getTunnel().listenHost, port);
    }

    private void unmapPort(String hostname) {
        _context.portMapper().unregister(PortMapper.SVC_HTTP_PROXY_TABBED + "@" +
                hostname);
        _context.portMapper().unregister(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" +
                hostname);
    }

    private int findRandomOpenPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0);) {
            return socket.getLocalPort();
        }
    }

    public I2PTunnelHTTPClient getI2PTunnelHTTPClient(URI uri) {
        String hostname = uri.getHost();
        return getI2PTunnelHTTPClient(hostname);
    }

    public I2PTunnelHTTPClient getI2PTunnelHTTPClient(String hostname) {
        if (hostname == null)
            return null;
        Destination destination = _context.namingService().lookup(hostname);
        if (destination == null)
            return null;
        return clients.get(destination);
    }

    protected boolean mapNewClient(URI uri) {
        String hostname = uri.getHost();
        if (hostname == null)
            return false;
        Destination destination = _context.namingService().lookup(hostname);
        if (destination == null)
            return false;
        if (getI2PTunnelHTTPClient(uri) != null)
            return false;
        try {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Mapping new HTTP client for destination:" + uri.getHost() + "/" + destination.toBase32());
            int port = findRandomOpenPort();
            I2PTunnelHTTPClient client = new I2PTunnelHTTPClient(
                    port, l, _ownDest, hostname, getEventDispatcher(), getTunnel());
            clients.put(destination, client);
            getI2PTunnelHTTPClient(hostname).startRunning();
            mapPort(hostname, port);
        } catch (IOException e) {
            throw new RuntimeException("Failed to find a random open port", e);
        }
        return true;
    }

    protected boolean unmapClient(URI uri) {
        String hostname = uri.getHost();
        if (hostname == null)
            return false;
        if (getI2PTunnelHTTPClient(hostname) != null) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Unmapping and shutting down HTTP client for desintation: " + hostname);
            getI2PTunnelHTTPClient(hostname).close(true);
            unmapPort(hostname);
            return true;
        }
        return false;
    }

    @Override
    protected void clientConnectionRun(Socket s) {
        OutputStream out = null;

        // in-net outproxy
        boolean usingWWWProxy = false;

        long requestId = __requestId.incrementAndGet();
        I2PSocket i2ps = null;
        String targetRequest = null;
        String currentProxy = null;
        try {
            int requestCount = 0;
            s.setSoTimeout(INITIAL_SO_TIMEOUT);
            out = s.getOutputStream();
            InputReader reader = new InputReader(s.getInputStream());
            HTTPRequestReader hrr = new HTTPRequestReader(s, _context, reader, usingWWWProxy, __requestId,
                    BROWSER_READ_TIMEOUT, getTunnel(), this);
            _log.debug("clientConnectionRun on Tab-Aware Proxy to" + hrr.toString(), new Exception("I did it :)."));
            if (hrr.originSeparator() == null) {
                if (_log.shouldLog(Log.WARN))
                    _log.warn("Invalid URL used as origin in tab-aware proxy");
                return;
            }
            if (mapNewClient(hrr.originSeparator())) {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("Set up a new tab-aware proxy for: " + hrr.originSeparator());
            } else {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("A tab-aware proxy for: " + hrr.originSeparator() + "already existed. Re-using it.");
            }
            targetRequest = hrr.getTargetRequest();
            currentProxy = hrr.getCurrentProxy();
            I2PTunnelHTTPClient httpClient = getI2PTunnelHTTPClient(hrr.originSeparator());
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Locally-isolated destination for:" + hrr.originSeparator().getHost() + " is on: "
                        + httpClient.getLocalPort());

            boolean keepalive = getBooleanOption(OPT_KEEPALIVE_BROWSER, DEFAULT_KEEPALIVE_BROWSER) &&
                    !(s instanceof InternalSocket);
            do {
                if (hrr.getNewRequest().length() > 0 && _log.shouldDebug())
                    _log.debug(getPrefix(requestId) + "hrr.getNewRequest() header: [" + hrr.getNewRequest() + ']');

                if (hrr.getMethod() == null || (hrr.getDestination() == null && !hrr.getUsingInternalOutproxy())) {
                    if (requestCount > 0) {
                        // SocketTimeout, normal to get here for persistent connections,
                        // because DataHelper.readLine() returns null on EOF
                        return;
                    }
                    _log.debug("No HTTP hrr.getMethod() found in the request.");
                    try {
                        if (hrr.getProtocol() != null && "http".equals(hrr.getProtocol().toLowerCase(Locale.US))) {
                            out.write(getErrorPage("denied", ERR_REQUEST_DENIED).getBytes("UTF-8"));
                        } else {
                            out.write(getErrorPage("protocol", ERR_BAD_PROTOCOL).getBytes("UTF-8"));
                        }
                        writeFooter(out);
                    } catch (IOException ioe) {
                        // ignore
                    }
                    return;
                }

                if (_log.shouldLog(Log.DEBUG)) {
                    _log.debug(getPrefix(requestId) + "Destination: " + hrr.getDestination());
                }

                // Authorization
                // Yes, this is sent and checked for every request on a persistent connection
                AuthResult result = authorize(s, requestId, hrr.getMethod(), hrr.getAuthorization());
                if (result != AuthResult.AUTH_GOOD) {
                    if (_log.shouldLog(Log.WARN)) {
                        if (hrr.getAuthorization() != null) {
                            _log.warn(getPrefix(requestId) + "Auth failed, sending 407 again");
                        } else {
                            _log.warn(getPrefix(requestId) + "Auth required, sending 407");
                        }
                    }
                    try {
                        out.write(getAuthError(result == AuthResult.AUTH_STALE).getBytes("UTF-8"));
                        writeFooter(out);
                    } catch (IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // Serve local proxy files (images, css linked from error pages)
                // Ignore all the headers
                if (hrr.getUsingInternalServer()) {
                    try {
                        // disable the add form if address helper is disabled
                        if (hrr.getInternalPath().equals("/add") &&
                                Boolean.parseBoolean(getTunnel().getClientOptions().getProperty(PROP_DISABLE_HELPER))) {
                            out.write(I2PTunnelHTTPClient.ERR_HELPER_DISABLED.getBytes("UTF-8"));
                        } else {
                            LocalHTTPServer.serveLocalFile(_context, sockMgr, out, hrr.getMethod(),
                                    hrr.getInternalPath(),
                                    hrr.getInternalRawQuery(), _proxyNonce, hrr.getAllowGzip());
                        }
                    } catch (IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // no destination, going to outproxy plugin
                if (hrr.getUsingInternalOutproxy()) {
                    Socket outSocket = hrr.getOutproxy().connect(hrr.getHost(), hrr.getRemotePort());
                    OnTimeout onTimeout = new OnTimeout(s, s.getOutputStream(), hrr.getTargetRequest(), usingWWWProxy,
                            hrr.getCurrentProxy(), requestId);
                    byte[] data;
                    byte[] response;
                    if (hrr.getIsConnect()) {
                        data = null;
                        response = SUCCESS_RESPONSE.getBytes("UTF-8");
                    } else {
                        data = hrr.getNewRequest().toString().getBytes("ISO-8859-1");
                        response = null;
                    }
                    Thread t = new I2PTunnelOutproxyRunner(s, outSocket, sockLock, data, response, onTimeout);
                    // we are called from an unlimited thread pool, so run inline
                    // t.start();
                    t.run();
                    return;
                }

                // LOOKUP
                // If the host is "i2p", the getHostName() lookup failed, don't try to
                // look it up again as the naming service does not do negative caching
                // so it will be slow.
                Destination clientDest = null;
                String addressHelper = addressHelpers.get(hrr.getDestination().toLowerCase(Locale.US));
                if (addressHelper != null) {
                    clientDest = _context.namingService().lookup(addressHelper);
                    if (clientDest == null) {
                        // remove bad entries
                        addressHelpers.remove(hrr.getDestination().toLowerCase(Locale.US));
                        if (_log.shouldLog(Log.WARN)) {
                            _log.warn(getPrefix(requestId) + "Could not find destination for " + addressHelper);
                        }
                        String header = getErrorPage("ahelper-notfound", ERR_AHELPER_NOTFOUND);
                        try {
                            writeErrorMessage(header, out, hrr.getTargetRequest(), false, hrr.getDestination());
                        } catch (IOException ioe) {
                            // ignore
                        }
                        return;
                    }
                } else if ("i2p".equals(hrr.getHost())) {
                    clientDest = null;
                } else if (hrr.getDestination().toLowerCase(Locale.US).endsWith(".b32.i2p")) {
                    int len = hrr.getDestination().length();
                    if (len < 60 || (len >= 61 && len <= 63)) {
                        // 8-59 or 61-63 chars, this won't work
                        String header = getErrorPage("b32", ERR_DESTINATION_UNKNOWN);
                        try {
                            writeErrorMessage(header, _t("Corrupt Base32 address"), out, hrr.getTargetRequest(), false,
                                    hrr.getDestination());
                        } catch (IOException ioe) {
                        }
                        return;
                    }
                    if (len >= 64) {
                        // catch b33 errors before session lookup
                        try {
                            BlindData bd = Blinding.decode(_context, hrr.getDestination());
                            if (_log.shouldWarn())
                                _log.warn("Resolved b33 " + bd);
                            // TESTING
                            // sess.sendBlindingInfo(bd, 24*60*60*1000);
                        } catch (IllegalArgumentException iae) {
                            if (_log.shouldWarn())
                                _log.warn("Unable to resolve b33 " + hrr.getDestination(), iae);
                            // b33 error page
                            String header = getErrorPage("b32", ERR_DESTINATION_UNKNOWN);
                            try {
                                writeErrorMessage(header, iae.getMessage(), out, hrr.getTargetRequest(), false,
                                        hrr.getDestination());
                            } catch (IOException ioe) {
                            }
                            return;
                        }
                    }
                    // use existing session to look up for efficiency
                    verifySocketManager();
                    I2PSession sess = sockMgr.getSession();
                    if (!sess.isClosed()) {
                        if (len == 60) {
                            byte[] hData = Base32.decode(hrr.getDestination().substring(0, 52));
                            if (hData != null) {
                                if (_log.shouldInfo())
                                    _log.info("lookup b32 in-session " + hrr.getDestination());
                                Hash hash = Hash.create(hData);
                                clientDest = sess.lookupDest(hash, 20 * 1000);
                            } else {
                                clientDest = null;
                            }
                        } else if (len >= 64) {
                            if (_log.shouldInfo())
                                _log.info("lookup b33 in-session " + hrr.getDestination());
                            LookupResult lresult = sess.lookupDest2(hrr.getDestination(), 20 * 1000);
                            clientDest = lresult.getDestination();
                            int code = lresult.getResultCode();
                            if (code != LookupResult.RESULT_SUCCESS) {
                                if (_log.shouldWarn())
                                    _log.warn("Unable to resolve b33 " + hrr.getDestination() + " error code " + code);
                                if (code != LookupResult.RESULT_FAILURE) {
                                    // form to supply missing data
                                    writeB32SaveForm(out, hrr.getDestination(), code, hrr.getTargetRequest());
                                    return;
                                }
                                // fall through to standard destination unreachable error page
                            }
                        }
                    } else {
                        if (_log.shouldInfo())
                            _log.info("lookup b32 out of session " + hrr.getDestination());
                        // TODO can't get result code from here
                        clientDest = _context.namingService().lookup(hrr.getDestination());
                    }
                } else {
                    if (_log.shouldInfo())
                        _log.info("lookup hostname " + hrr.getDestination());
                    clientDest = _context.namingService().lookup(hrr.getDestination());
                }

                if (clientDest == null) {
                    // l.log("Could not resolve " + destination + ".");
                    if (_log.shouldLog(Log.WARN)) {
                        _log.warn("Unable to resolve " + hrr.getDestination() + " (proxy? " + usingWWWProxy
                                + ", request: "
                                + hrr.getTargetRequest());
                    }
                    String header;
                    String jumpServers = null;
                    String extraMessage = null;
                    if (usingWWWProxy) {
                        header = getErrorPage("dnfp", ERR_DESTINATION_UNKNOWN);
                    } else if (hrr.getAhelperPresent()) {
                        header = getErrorPage("dnfb", ERR_DESTINATION_UNKNOWN);
                    } else if (hrr.getDestination().length() >= 60
                            && hrr.getDestination().toLowerCase(Locale.US).endsWith(".b32.i2p")) {
                        header = getErrorPage("nols", ERR_DESTINATION_UNKNOWN);
                        extraMessage = _t("Destination lease set not found");
                    } else {
                        header = getErrorPage("dnfh", ERR_DESTINATION_UNKNOWN);
                        jumpServers = getTunnel().getClientOptions().getProperty(PROP_JUMP_SERVERS);
                        if (jumpServers == null) {
                            jumpServers = DEFAULT_JUMP_SERVERS;
                        }
                        int jumpDelay = 400 + _context.random().nextInt(256);
                        try {
                            Thread.sleep(jumpDelay);
                        } catch (InterruptedException ie) {
                        }
                    }
                    try {
                        writeErrorMessage(header, extraMessage, out, hrr.getTargetRequest(), usingWWWProxy,
                                hrr.getDestination(),
                                jumpServers);
                    } catch (IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // as of 0.9.35, allowInternalSSL defaults to true, and overridden to true
                // unless PROP_SSL_SET is set
                if (hrr.getIsConnect() &&
                        !usingWWWProxy &&
                        getTunnel().getClientOptions().getProperty(PROP_SSL_SET) != null &&
                        !Boolean.parseBoolean(getTunnel().getClientOptions().getProperty(PROP_INTERNAL_SSL, "true"))) {
                    try {
                        writeErrorMessage(ERR_INTERNAL_SSL, out, hrr.getTargetRequest(), false, hrr.getDestination());
                    } catch (IOException ioe) {
                        // ignore
                    }
                    if (_log.shouldLog(Log.WARN))
                        _log.warn("SSL to i2p destinations denied by configuration: " + hrr.getTargetRequest());
                    return;
                }

                // Address helper response form
                // This will only load once - the second time it won't be "new"
                // Don't do this for eepget, which uses a user-agent of "Wget"
                if (hrr.getAhelperNew() && "GET".equals(hrr.getMethod()) &&
                        (hrr.getUserAgent() == null || !hrr.getUserAgent().startsWith("Wget")) &&
                        !Boolean.parseBoolean(getTunnel().getClientOptions().getProperty(PROP_DISABLE_HELPER))) {
                    try {
                        writeHelperSaveForm(out, hrr.getDestination(), hrr.getAhelperKey(), hrr.getTargetRequest(),
                                hrr.getReferer());
                    } catch (IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // Redirect to non-addresshelper URL to not clog the browser address bar
                // and not pass the parameter to the I2P Site.
                // This also prevents the not-found error page from looking bad
                // Syndie can't handle a redirect of a POST
                if (hrr.getAhelperPresent() && !"POST".equals(hrr.getMethod()) && !"PUT".equals(hrr.getMethod())) {
                    String uri = hrr.getTargetRequest();
                    if (_log.shouldLog(Log.DEBUG)) {
                        _log.debug("Auto redirecting to " + uri);
                    }
                    try {
                        out.write(("HTTP/1.1 301 Address Helper Accepted\r\n" +
                                "Location: " + uri + "\r\n" +
                                "Connection: close\r\n" +
                                "\r\n").getBytes("UTF-8"));
                    } catch (IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // Close persistent I2PSocket if destination or port changes
                // and open a new one.
                // We do not maintain a pool of open I2PSockets or look for
                // an available one. Keep it very simple.
                // As long as the traffic keeps going to the same place
                // we will keep reusing it.
                // While we should be able to reuse it if only the port changes,
                // that should be extremely rare, so don't bother.
                // For common use patterns including outproxy use,
                // this should still be quite effective.
                if (i2ps == null || i2ps.isClosed() ||
                        hrr.getRemotePort() != i2ps.getPort() ||
                        !clientDest.equals(i2ps.getPeerDestination())) {
                    if (i2ps != null) {
                        if (_log.shouldInfo())
                            _log.info("Old socket closed or different dest/port, opening new one");
                        try {
                            i2ps.close();
                        } catch (IOException ioe) {
                        }
                    }
                    Properties opts = new Properties();
                    // opts.setProperty("i2p.streaming.inactivityTimeout", ""+120*1000);
                    // 1 == disconnect. see ConnectionOptions in the new streaming lib, which i
                    // dont want to hard link to here
                    // opts.setProperty("i2p.streaming.inactivityTimeoutAction", ""+1);
                    I2PSocketOptions sktOpts;
                    try {
                        sktOpts = getDefaultOptions(opts);
                    } catch (RuntimeException re) {
                        // tunnel build failure
                        StringBuilder buf = new StringBuilder(128);
                        buf.append("HTTP/1.1 503 Service Unavailable");
                        if (re.getMessage() != null)
                            buf.append(" - ").append(re.getMessage());
                        buf.append("\r\n\r\n");
                        try {
                            out.write(buf.toString().getBytes("UTF-8"));
                        } catch (IOException ioe) {
                        }
                        throw re;
                    }
                    if (hrr.getRemotePort() > 0)
                        sktOpts.setPort(hrr.getRemotePort());
                    i2ps = createI2PSocket(clientDest, sktOpts);
                }

                I2PTunnelRunner t;
                I2PTunnelHTTPClientRunner hrunner = null;
                if (hrr.getIsConnect()) {
                    byte[] data;
                    byte[] response;
                    if (usingWWWProxy) {
                        data = hrr.getNewRequest().toString().getBytes("ISO-8859-1");
                        response = null;
                    } else {
                        data = null;
                        response = SUCCESS_RESPONSE.getBytes("UTF-8");
                    }
                    // no OnTimeout, we can't send HTTP error responses after sending
                    // SUCCESS_RESPONSE.
                    t = new I2PTunnelRunner(s, i2ps, sockLock, data, response, mySockets, (OnTimeout) null);
                } else {
                    byte[] data = hrr.getNewRequest().toString().getBytes("ISO-8859-1");
                    OnTimeout onTimeout = new OnTimeout(s, s.getOutputStream(), hrr.getTargetRequest(), usingWWWProxy,
                            hrr.getCurrentProxy(), requestId, hrr.getHostLowerCase(), hrr.getIsConnect());
                    boolean keepaliveI2P = keepalive && getBooleanOption(OPT_KEEPALIVE_I2P, DEFAULT_KEEPALIVE_I2P);
                    hrunner = new I2PTunnelHTTPClientRunner(s, i2ps, sockLock, data, mySockets, onTimeout,
                            keepaliveI2P, keepalive, hrr.getIsHead());
                    t = hrunner;
                }
                if (usingWWWProxy) {
                    t.setSuccessCallback(
                            new OnProxySuccess(hrr.getCurrentProxy(), hrr.getHostLowerCase(), hrr.getIsConnect()));
                }
                // we are called from an unlimited thread pool, so run inline
                // t.start();
                t.run();

                // I2PTunnelHTTPClientRunner spins off the browser-to-i2p thread and keeps
                // the i2p-to-socket copier in-line. So we won't get here until the i2p socket
                // is closed.
                // check if whatever was in the response does not allow keepalive
                if (keepalive && hrunner != null && !hrunner.getKeepAliveSocket())
                    break;
                // The old I2P socket was closed, null it out so we'll get a new one
                // next time around
                if (hrunner != null && !hrunner.getKeepAliveI2P())
                    i2ps = null;
                // go around again
                requestCount++;
            } while (keepalive);

        } catch (IOException ex) {
            // This is normal for keepalive when the browser closed the socket,
            // or a SocketTimeoutException if we gave up first
            if (_log.shouldLog(Log.INFO)) {
                _log.info(getPrefix(requestId) + "Error trying to connect", ex);
            }

            handleClientException(ex, out, targetRequest, usingWWWProxy, currentProxy,
                    requestId);
        } catch (I2PException ex) {
            if (_log.shouldLog(Log.INFO)) {
                _log.info(getPrefix(requestId) + "Error trying to connect",
                        ex);
            }
            handleClientException(ex, out, targetRequest, usingWWWProxy,
                    currentProxy, requestId);
        } catch (OutOfMemoryError oom) {
            IOException ex = new IOException("OOM");
            _log.error(getPrefix(requestId) + "Error trying to connect", oom);
            handleClientException(ex, out, targetRequest, usingWWWProxy,
                    currentProxy, requestId);
        } finally {
            // only because we are running it inline
            closeSocket(s);
            if (i2ps != null)
                try {
                    i2ps.close();
                } catch (IOException ioe) {
                }
        }
    }
}
