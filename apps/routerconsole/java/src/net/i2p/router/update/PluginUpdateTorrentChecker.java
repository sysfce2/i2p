package net.i2p.router.update;

import java.io.File;
import java.net.URI;
import java.util.List;

import net.i2p.crypto.TrustedUpdate;
import net.i2p.router.RouterContext;
import net.i2p.router.web.ConfigUpdateHandler;
import net.i2p.update.UpdateMethod;
import net.i2p.update.UpdateType;
import net.i2p.util.PartialEepGet;
import net.i2p.util.PortMapper;

public class PluginUpdateTorrentChecker extends UpdateRunner {
    private final String _appName;
    private final String _oldVersion;
    private final URI _torrentURI;

    public PluginUpdateTorrentChecker(RouterContext ctx, ConsoleUpdateManager mgr,
                               List<URI> uris, String appName, String oldVersion ) { 
        super(ctx, mgr, UpdateType.PLUGIN, uris, oldVersion);
        if (!uris.isEmpty())
            _currentURI = uris.get(0);
        if (uris.size() == 2)
            _torrentURI = uris.get(1);
        else
            _torrentURI = null;
        _appName = appName;
        _oldVersion = oldVersion;
    }
    
    @Override
    public String getID() { return _appName; }

    @Override
    public void update() {
        boolean httpSeed = updateCheckHTTP();
        if (httpSeed) {
            boolean torrentSeed = updateCheckTorrent();
            if (!torrentSeed) {
                _mgr.notifyCheckComplete(this, false, false);
            } else {
                
            }
        } else {
            _mgr.notifyCheckComplete(this, false, false);
        }
    }
    
    protected boolean updateCheckHTTP() {
        return updateCheck(_currentURI.toString(), false);
    }

    protected boolean updateCheckTorrent() {
        return updateCheck(_torrentURI.toString(), true);
    }

    protected boolean updateCheck(String uriString, boolean torrent) {
        if (_torrentURI != null)
            return false;
        _isPartial = torrent;
        // performs exactly the same update check as PluginUpdateChecker
        // but returns a boolean value
        String proxyHost = _context.getProperty(ConfigUpdateHandler.PROP_PROXY_HOST, ConfigUpdateHandler.DEFAULT_PROXY_HOST);
        int proxyPort = ConfigUpdateHandler.proxyPort(_context);
        if (proxyPort == ConfigUpdateHandler.DEFAULT_PROXY_PORT_INT &&
            proxyHost.equals(ConfigUpdateHandler.DEFAULT_PROXY_HOST) &&
            _context.portMapper().getPort(PortMapper.SVC_HTTP_PROXY) < 0) {
            String msg = _t("HTTP client proxy tunnel must be running");
            if (_log.shouldWarn())
                _log.warn(msg);
            updateStatus("<b>" + msg + "</b>");
            return false;
        }
        updateStatus("<b>" + _t("Checking for update of plugin {0}", _appName) + "</b>");
        _baos.reset();
        try {
            _get = new PartialEepGet(_context, proxyHost, proxyPort, _baos, uriString, TrustedUpdate.HEADER_BYTES);
            if (torrent)
                _get.addStatusListener(this);
            return _get.fetch(CONNECT_TIMEOUT);
        } catch (Throwable t) {
            _log.error("Error checking update for plugin", t);
        }
        return false;
    }

    @Override
    public void bytesTransferred(long alreadyTransferred, int currentWrite, long bytesTransferred, long bytesRemaining, String url) {
    }

    @Override
    public void transferComplete(long alreadyTransferred, long bytesTransferred, long bytesRemaining,
                                    String url, String outputFile, boolean notModified) {
        super.transferComplete(alreadyTransferred, bytesTransferred, bytesRemaining,
                                url, outputFile, notModified);
        // super sets _newVersion if newer
        boolean newer = _newVersion != null;
        if (newer) {
            _mgr.notifyVersionAvailable(this, _currentURI, UpdateType.PLUGIN, _appName, UpdateMethod.HTTP,
                                        _urls, _newVersion, _oldVersion);
        }
        _mgr.notifyCheckComplete(this, newer, true);
    }

    @Override
    public void transferFailed(String url, long bytesTransferred, long bytesRemaining, int currentAttempt) {
        File f = new File(_updateFile);
        f.delete();
        _mgr.notifyCheckComplete(this, false, false);
    }
}
