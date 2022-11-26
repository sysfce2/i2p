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
    if (_log.shouldInfo())
      _log.info("Checking cachedHeader header prefix" + cacheableHeader);
    if (cachedHeader != null)
      return;
    if (cacheableHeader == null)
      return;
    if (cacheableHeader.equals(""))
      return;
    cachedHeader = cacheableHeader;
    if (_log.shouldInfo())
      _log.info("Caching cachedHeader header prefix" + cachedHeader);
  }

  private synchronized boolean shouldRecheck() {
    boolean settable = (cachedHeader == null);
    if (!settable)
      return settable;
    if (lastFailure == -1) {
      lastFailure = System.currentTimeMillis();
      if (_log.shouldDebug())
        _log.debug(
            "New instance, attempting to set cachedHeader header for the first time");
      return settable;
    }
    if ((System.currentTimeMillis() - lastFailure) > cacheTimeout) {
      lastFailure = System.currentTimeMillis();
      if (_log.shouldDebug())
        _log.debug(
            "More than ten minutes since failing attempt to re-check cachedHeader header");
      return settable;
    }
    if (_log.shouldDebug())
      _log.debug("Not attempting to re-check cachedHeader header");
    return false;
  }

  private boolean isFromI2P(final HttpServletRequest httpRequest) {
    final String hashHeader = httpRequest.getHeader("X-I2P-DestHash");
    if (hashHeader == null) {
      return true;
    }
    return false;
  }

  /**

   */
  abstract public String getCachableHeader(final Request request);

  abstract public String headerContents(final HttpServletRequest httpRequest);

  private void setHeader(final Request request,
                         final HttpServletRequest httpRequest,
                         HttpServletResponse httpResponse) {
    if (shouldRecheck()) {
      String cacheableHeader = getCachableHeader(request);
      if (_log.shouldInfo())
        _log.info("Checking cachedHeader header IP " + request.getLocalAddr() +
                  " port " + request.getLocalPort() + " prefix " +
                  cacheableHeader);
      setCachedHeader(cacheableHeader);
    }
    String headerValue = headerContents(httpRequest);
    if (headerValue != null) {
      if (_log.shouldInfo())
        _log.info("Checking cachedHeader header" + headerValue);
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
}
