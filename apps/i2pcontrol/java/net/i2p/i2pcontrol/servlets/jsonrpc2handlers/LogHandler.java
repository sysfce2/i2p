package net.i2p.i2pcontrol.servlets.jsonrpc2handlers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.thetransactioncompany.jsonrpc2.JSONRPC2Error;
import com.thetransactioncompany.jsonrpc2.JSONRPC2Request;
import com.thetransactioncompany.jsonrpc2.JSONRPC2Response;
import com.thetransactioncompany.jsonrpc2.server.MessageContext;
import com.thetransactioncompany.jsonrpc2.server.RequestHandler;

import net.i2p.I2PAppContext;
import net.i2p.router.RouterContext;
import net.i2p.util.Log;
import net.i2p.util.LogManager;

public class LogHandler implements RequestHandler {
    private final RouterContext _context;
    private final Log _log;
    private static final String[] requiredArgs = { "Info" };
    private final JSONRPC2Helper _helper;

    public LogHandler(RouterContext ctx, JSONRPC2Helper helper) {
        _helper = helper;
        _context = ctx;
        if (ctx != null)
            _log = ctx.logManager().getLog(I2PControlHandler.class);
        else
            _log = I2PAppContext.getGlobalContext().logManager().getLog(I2PControlHandler.class);
    }

    // Reports the method names of the handled requests
    public String[] handledRequests() {
        return new String[] { "Info" };
    }

    // Processes the requests
    public JSONRPC2Response process(JSONRPC2Request req, MessageContext ctx) {
        if (req.getMethod().equals("Info")) {
            JSONRPC2Error err = _helper.validateParams(requiredArgs, req);
            if (err != null)
                return new JSONRPC2Response(err, req.getID());

            Map<String, Object> inParams = req.getNamedParams();
            String selector = (String) inParams.get("Info");
            Map<String, Object> outParams = new HashMap<String, Object>(4);
            LogManager logManager = _context.logManager();
            if (selector != null && !selector.isEmpty()) {
                String echo = logManager.getLog(selector).toString();
                outParams.put("Result", echo);
                return new JSONRPC2Response(outParams, req.getID());
            } else {
                List<String> echoArray = logManager.getBuffer().getMostRecentMessages();
                String echo = String.join("\n", echoArray);
                outParams.put("Result", echo);
                return new JSONRPC2Response(outParams, req.getID());
            }
        } else {
            // Method name not supported
            return new JSONRPC2Response(JSONRPC2Error.METHOD_NOT_FOUND, req.getID());
        }
    }
}
