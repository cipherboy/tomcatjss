package org.dogtagpki.tomcat;

import java.security.Provider;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FIPSContext implements org.apache.tomcat.util.net.SSLContext {
    public static Logger logger = LoggerFactory.getLogger(FIPSContext.class);

    private javax.net.ssl.SSLContext ctx;
    private SSLParameters params;

    private KeyManager[] kms;
    private TrustManager[] tms;

    public FIPSContext(String alias, javax.net.ssl.SSLContext ctx) {
        logger.debug("FIPSContext(" + alias + ", ...");
        ctx = ctx;
    }

    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        logger.debug("FIPSContext.init(...)");

        try {
            if (ctx == null) {
                ctx = javax.net.ssl.SSLContext.getInstance("TLS", "SunJSSE");
            }

            ctx.init(kms, tms, sr);
        } catch (Exception e) {
            throw new KeyManagementException(e.getMessage(), e);
        }
    }

    public javax.net.ssl.SSLEngine createSSLEngine() {
        logger.debug("FIPSContext.createSSLEngine()");

        return ctx.createSSLEngine();
    }

    public javax.net.ssl.SSLSessionContext getServerSessionContext() {
        logger.debug("FIPSContext.getServerSessionContext()");
        return ctx.getServerSessionContext();
    }

    public javax.net.ssl.SSLServerSocketFactory getServerSocketFactory() {
        logger.debug("FIPSContext.getServerSocketFactory()");
        return ctx.getServerSocketFactory();
    }

    public javax.net.ssl.SSLParameters getSupportedSSLParameters() {
        logger.debug("FIPSContext.getSupportedSSLParameters()");
        return ctx.getSupportedSSLParameters();
    }

    public java.security.cert.X509Certificate[] getCertificateChain(java.lang.String alias) {
        logger.debug("FIPSContext.getCertificateChain(" + alias + ")");

        for (KeyManager km : kms) {
            try {
                X509KeyManager xkm = (X509KeyManager) km;
                return xkm.getCertificateChain(alias);
            } catch (Exception e) {
                logger.debug("FIPSContext.getCertificateChain: " + e);
            }
        }

        return null;
    }

    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        logger.debug("FIPSContext.getAcceptedIssuers()");

        ArrayList<java.security.cert.X509Certificate> issuers = new ArrayList<java.security.cert.X509Certificate>();

        for (TrustManager tm : tms) {
            try {
                X509TrustManager xtm = (X509TrustManager) tm;
                for (java.security.cert.X509Certificate cert : xtm.getAcceptedIssuers()) {
                    issuers.add(cert);
                }
            } catch (Exception e) {
                logger.debug("FIPSContext.getAcceptedIssuers: " + e);
            }
        }

        return issuers.toArray(new java.security.cert.X509Certificate[0]);
    }

    public void destroy() {
        logger.debug("FIPSContext.destory()");
    }
}
