package net.i2p.servlet.filters;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.i2p.I2PAppContext;
import net.i2p.I2PException;
import net.i2p.data.DataHelper;
import net.i2p.data.Destination;
import net.i2p.data.PrivateKeyFile;
import net.i2p.util.Log;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.HandlerWrapper;

/**
 * Abstract class that allows implementers to easily manipulate headers for I2P
 * sites. It provides configuration, caching, and the ability to differentate
 * between requests coming from I2P and requests coming from the clearweb.
 *
 *  @String cachedHeader a value which can be either a whole header "Value" or a
 * fragment of one
 *  @String headerKey a value which is the "Key" in the header applied to the
 * response.
 *  @boolean applyToI2P set to true to apply the header to responses bound to
 * I2P clients
 *  @boolean applyToClearnet set to true to apply the header tor responses bound
 * to non-I2P clients
 *  @long cacheTimeout a value in milliseconds to wait before re-computing a
 * cachedHeader value
 *
 *  @since 0.9.57
 */
public abstract class XI2PHeaderFilter extends HandlerWrapper {
  public String cachedHeader = null;
  public String headerKey = null;
  public boolean applyToI2P = false;
  public boolean applyToClearnet = false;

  private long lastFailure = -1;
  public final long cacheTimeout;
  public static final String encodeUTF = StandardCharsets.UTF_8.toString();

  public XI2PHeaderFilter(final long ft) { cacheTimeout = ft; }

  protected final Log _log =
      I2PAppContext.getGlobalContext().logManager().getLog(
          XI2PHeaderFilter.class);

  private synchronized void setCachedHeader(String cacheableHeader) {
    if (_log.shouldInfo()) {
      _log.info("Checking cachedHeader header prefix" + cacheableHeader);
    }
    if (cachedHeader != null) {
      return;
    }
    if (cacheableHeader == null) {
      return;
    }
    if (cacheableHeader.equals("")) {
      return;
    }

    cachedHeader = cacheableHeader;
    if (_log.shouldInfo()) {
      _log.info("Caching cachedHeader header prefix" + cachedHeader);
    }
  }

  private synchronized boolean shouldRecheck() {
    boolean settable = (cachedHeader == null);
    if (!settable) {
      return settable;
    }
    if (lastFailure == -1) {
      lastFailure = System.currentTimeMillis();
      if (_log.shouldDebug()) {
        _log.debug(
            "New instance, attempting to set cachedHeader header for the first time");
      }
      return settable;
    }
    if ((System.currentTimeMillis() - lastFailure) > cacheTimeout) {
      lastFailure = System.currentTimeMillis();
      if (_log.shouldDebug()) {
        _log.debug(
            "More than ten minutes since failing attempt to re-check cachedHeader header");
      }
      return settable;
    }
    if (_log.shouldDebug()) {
      _log.debug("Not attempting to re-check cachedHeader header");
    }
    return false;
  }

  protected boolean isFromI2P(final HttpServletRequest httpRequest) {
    final String hashHeader = httpRequest.getHeader("X-I2P-DestHash");
    if (hashHeader == null) {
      return true;
    }
    return false;
  }

  /**
   * getCachableHeader obtains the "cacheable" part of a header and stores
   * it in the cachedHeader variable.
   *
   * @param httpRequest the HttpServletRequest from the caller
   * @param request the Request from the caller
   * @return String the cachable part of the header
   *
   */
  public abstract String getCachableHeader(final HttpServletRequest httpRequest,
                                           final Request request);

  /**
   * headerContents computes the final contents which will be used as the header
   * "Key" in the key-value pair.
   *
   * @param httpRequest the HttpServletRequest from the caller
   * @param request the Request from the caller
   * @return the full header
   *
   */
  public abstract String headerContents(final HttpServletRequest httpRequest,
                                        final Request request);

  private void setHeader(final Request request,
                         final HttpServletRequest httpRequest,
                         HttpServletResponse httpResponse) {
    if (shouldRecheck()) {
      String cacheableHeader = getCachableHeader(httpRequest, request);
      if (_log.shouldInfo()) {
        _log.info("Checking cachedHeader header IP " + request.getLocalAddr() +
                  " port " + request.getLocalPort() + " prefix " +
                  cacheableHeader);
      }
      setCachedHeader(cacheableHeader);
    }
    String headerValue = headerContents(httpRequest, request);
    if (headerValue != null) {
      if (_log.shouldInfo()) {
        _log.info("Checking cachedHeader header" + headerValue);
      }
      httpResponse.addHeader(headerKey, headerValue);
    }
  }

  @Override
  public void handle(final String target, final Request request,
                     final HttpServletRequest httpRequest,
                     HttpServletResponse httpResponse)
      throws IOException, ServletException {
    if (headerKey != null) {
      // final String hashHeader = httpRequest.getHeader("X-I2P-DestHash");
      if (isFromI2P(httpRequest) && applyToI2P) {
        setHeader(request, httpRequest, httpResponse);
      }
      if (!isFromI2P(httpRequest) && applyToClearnet) {
        setHeader(request, httpRequest, httpResponse);
      }
    }
    _handler.handle(target, request, httpRequest, httpResponse);
  }

  protected synchronized Destination getTunnelDestination(String host,
                                                          String port) {
    Properties tunnelProps = getTunnelProperties(host, port);
    File configDir = I2PAppContext.getGlobalContext().getConfigDir();
    String kf = tunnelProps.getProperty("privKeyFile");
    if (kf != null) {
      File keyFile = new File(kf);
      if (!keyFile.isAbsolute()) {
        keyFile = new File(configDir, kf);
      }
      if (keyFile.exists()) {
        PrivateKeyFile pkf = new PrivateKeyFile(keyFile);
        try {
          return pkf.getDestination();
        } catch (I2PException e) {
          if (_log.shouldWarn()) {
            _log.warn(
                "I2PException Unable to get Destination value, keys arent ready. This is probably safe to ignore and will go away after the first run." +
                e);
          }
          return null;
        } catch (IOException e) {
          if (_log.shouldWarn()) {
            _log.warn(
                "IOE Unable to get Destination value, location is uninitialized due file not found. This probably means the keys aren't ready. This is probably safe to ignore." +
                e);
          }
          return null;
        }
      }
      _log.warn(
          "Unable to get Destination value, location is not a service tunnel.");
    }
    return null;
  }

  private synchronized Properties getTunnelProperties(String host,
                                                      String port) {
    File configDir = I2PAppContext.getGlobalContext().getConfigDir();
    File tunnelConfig = new File(configDir, "i2ptunnel.config");
    boolean isSingleFile = tunnelConfig.exists();
    if (!isSingleFile) {
      File tunnelConfigD = new File(configDir, "i2ptunnel.config.d");
      File[] configFiles =
          tunnelConfigD.listFiles(new net.i2p.util.FileSuffixFilter(".config"));
      if (configFiles == null) {
        return null;
      }
      for (int fnum = 0; fnum < configFiles.length; fnum++) {
        Properties tunnelProps = new Properties();
        try {
          DataHelper.loadProps(tunnelProps, configFiles[fnum]);
          String targetHost = tunnelProps.getProperty("targetHost");
          boolean hostmatch =
              (host.equals(targetHost) || "0.0.0.0".equals(targetHost) ||
               "::".equals(targetHost));
          if (hostmatch && port.equals(tunnelProps.getProperty("targetPort"))) {
            return tunnelProps;
          }
        } catch (IOException ioe) {
          if (_log.shouldWarn()) {
            _log.warn(
                "IOE Unable to find a spoofed hosntame, location is uninitialized. This is probably safe to ignore. location='" +
                ioe + "'");
          }
          return null;
        }
      }
    } else {
      // don't bother
    }
    return null;
  }

  protected synchronized String getSpoofedHostname(String host, String port) {
    Properties tunnelProps = getTunnelProperties(host, port);
    String sh = tunnelProps.getProperty("spoofedHost");
    if (sh != null) {
      if (sh.endsWith(".i2p")) {
        return sh;
      }
    }
    if (_log.shouldWarn()) {
      _log.warn("Unable to find a spoofed hostname in any file");
    }
    return null;
  }
}
