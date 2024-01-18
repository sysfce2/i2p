package net.i2p.router.update;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.IllegalArgumentException;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import net.i2p.CoreVersion;
import net.i2p.crypto.SU3File;
import net.i2p.crypto.TrustedUpdate;
import net.i2p.data.DataFormatException;
import net.i2p.data.DataHelper;
import net.i2p.data.SigningPublicKey;
import net.i2p.router.RouterContext;
import net.i2p.router.web.ConfigUpdateHandler;
import net.i2p.router.web.Messages;
import net.i2p.router.web.PluginStarter;
import net.i2p.router.web.RouterConsoleRunner;
import net.i2p.update.*;
import net.i2p.util.EepGet;
import net.i2p.util.FileUtil;
import net.i2p.util.Log;
import net.i2p.util.OrderedProperties;
import net.i2p.util.PortMapper;
import net.i2p.util.SecureDirectory;
import net.i2p.util.SecureFile;
import net.i2p.util.SystemVersion;
import net.i2p.util.VersionComparator;


/**
 * Check for an updated version of a plugin.
 * A plugin is a standard .sud file with a 40-byte signature,
 * a 16-byte version, and a .zip file.
 *
 * So we get the current version and update URL for the installed plugin,
 * then fetch the first 56 bytes of the URL, extract the version,
 * and compare.
 *
 * uri list must not be empty.
 *
 * Moved from web/ and turned into an UpdateTask.
 *
 * @since 0.9.4 moved from PluginUpdateHandler
 */
class PluginUpdateTorrentRunner extends PluginUpdateRunner {

    /*private String _appName;
    private final String _appDisplayName;
    private final String _oldVersion;
    private final URI _uri;
    private final String _xpi2pURL;
    private boolean _updated;*/
    private String _errMsg = "";

    private static final String XPI2P = "app.xpi2p";
    private static final String ZIP = XPI2P + ".zip";
    public static final String PLUGIN_DIR = PluginStarter.PLUGIN_DIR;
    private static final String PROP_ALLOW_NEW_KEYS = "routerconsole.allowUntrustedPlugins";

    public PluginUpdateTorrentRunner(RouterContext ctx, ConsoleUpdateManager mgr, List<URI> uris,
                              String appName, String oldVersion ) {
        super(ctx, mgr, uris, appName, oldVersion);
    }

        @Override
        protected void update() {

            _updated = false;
            if (_xpi2pURL.startsWith("file:") || _method == UpdateMethod.FILE) {
                // strip off file:// or just file:
                String xpi2pfile = _uri.getPath();
                if(xpi2pfile == null || xpi2pfile.length() == 0) {
                        statusDone("<b>" + _t("Bad URL {0}", _xpi2pURL) + "</b>");
                } else {
                    // copy the contents of from to _updateFile
                    long alreadyTransferred = (new File(xpi2pfile)).getAbsoluteFile().length();
                    if(FileUtil.copy((new File(xpi2pfile)).getAbsolutePath(), _updateFile, true, false)) {
                        updateStatus("<b>" + _t("Attempting to install from file {0}", _xpi2pURL) + "</b>");
                        transferComplete(alreadyTransferred, alreadyTransferred, 0L, _xpi2pURL, _updateFile, false);
                    } else {
                        statusDone("<b>" + _t("Failed to install from file {0}, copy failed.", _xpi2pURL) + "</b>");
                    }
                }
            } else {
                // use the same settings as for updater
                //boolean shouldProxy = _context.getProperty(ConfigUpdateHandler.PROP_SHOULD_PROXY, ConfigUpdateHandler.DEFAULT_SHOULD_PROXY);
                // always proxy, or else FIXME
                boolean shouldProxy = true;
                String proxyHost = _context.getProperty(ConfigUpdateHandler.PROP_PROXY_HOST, ConfigUpdateHandler.DEFAULT_PROXY_HOST);
                int proxyPort = ConfigUpdateHandler.proxyPort(_context);
                if (shouldProxy && proxyPort == ConfigUpdateHandler.DEFAULT_PROXY_PORT_INT &&
                    proxyHost.equals(ConfigUpdateHandler.DEFAULT_PROXY_HOST) &&
                    _context.portMapper().getPort(PortMapper.SVC_HTTP_PROXY) < 0) {
                    String msg = _t("HTTP client proxy tunnel must be running");
                    if (_log.shouldWarn())
                        _log.warn(msg);
                    statusDone("<b>" + msg + "</b>");
                    _mgr.notifyTaskFailed(this, msg, null);
                    return;
                }
                updateStatus("<b>" + _t("Downloading plugin from {0}", _xpi2pURL) + "</b>");
                try {
                    if (shouldProxy)
                        // 10 retries!!
                        _get = new EepGet(_context, proxyHost, proxyPort, 10, _updateFile, _xpi2pURL, false);
                    else
                        _get = new EepGet(_context, 1, _updateFile, _xpi2pURL, false);
                    _get.addStatusListener(PluginUpdateTorrentRunner.this);
                    _get.fetch(CONNECT_TIMEOUT, -1, shouldProxy ? INACTIVITY_TIMEOUT : NOPROXY_INACTIVITY_TIMEOUT);
                } catch (Throwable t) {
                    _log.error("Error downloading plugin", t);
                }
            }
            if (_updated) {
                _mgr.notifyComplete(this, _newVersion, null);
                _mgr.notifyComplete(this, _errMsg);
            } else {
                _mgr.notifyTaskFailed(this, _errMsg, null);
            }
        }

    /**
     *  Overridden to change the "Updating I2P" text in super
     *  @since 0.9.35
     */
    @Override
    public void bytesTransferred(long alreadyTransferred, int currentWrite, long bytesTransferred, long bytesRemaining, String url) {
        long d = currentWrite + bytesTransferred;
        String status = "<b>" + _t("Downloading plugin") + ": " + _appDisplayName + "</b>";
        _mgr.notifyProgress(this, status, d, d + bytesRemaining);
    }

        @Override
        public void transferComplete(long alreadyTransferred, long bytesTransferred, long bytesRemaining, String url, String outputFile, boolean notModified) {
            if (!(_xpi2pURL.startsWith("file:") || _method == UpdateMethod.FILE))
                updateStatus("<b>" + _t("Plugin downloaded") + ": " + _appDisplayName + "</b>");
            File f = new File(_updateFile);
            File appDir = new SecureDirectory(_context.getConfigDir(), PLUGIN_DIR);
            if ((!appDir.exists()) && (!appDir.mkdir())) {
                f.delete();
                statusDone("<b>" + _t("Cannot create plugin directory {0}", appDir.getAbsolutePath()) + "</b>");
                return;
            }
            boolean isSU3;
            try {
                isSU3 = isSU3File(f);
            } catch (IOException ioe) {
                f.delete();
                statusDone("<b>" + ioe + "</b>");
                return;
            }
            if (isSU3)
                processSU3(f, appDir, url);
            else
                processSUD(f, appDir, url);
        }

        /**
         *  @param pubkey null OK for su3
         *  @since 0.9.15
         */

        @Override
        public void transferFailed(String url, long bytesTransferred, long bytesRemaining, int currentAttempt) {
            File f = new File(_updateFile);
            f.delete();
            statusDone("<b>" + _t("Failed to download plugin from {0}", url) + "</b>");
        }

        private void statusDone(String msg) {
            // if we fail, we will pass this back in notifyTaskFailed()
            _errMsg = msg;
            updateStatus(msg);
        }

}

