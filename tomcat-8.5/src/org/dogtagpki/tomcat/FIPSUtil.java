/* BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2018 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.dogtagpki.tomcat;

import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLSessionContext;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.SSLUtilBase;

public class FIPSUtil extends SSLUtilBase {
    public static Log logger = LogFactory.getLog(FIPSUtil.class);

    private String keyAlias;

    private KeyManagerFactory kmf;
    private TrustManagerFactory tmf;
    private javax.net.ssl.SSLContext ctx;

    public FIPSUtil(SSLHostConfigCertificate cert, KeyManagerFactory kmf, TrustManagerFactory tmf) {
        super(cert);

        keyAlias = certificate.getCertificateKeyAlias();
        this.kmf = kmf;
        this.tmf = tmf;

        try {
            ctx = javax.net.ssl.SSLContext.getInstance("TLS", "SunJSSE");
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        logger.debug("FIPSUtil: instance created with alias=" + keyAlias);
    }

    @Override
    public KeyManager[] getKeyManagers() throws Exception {
        logger.debug("FIPSUtil: getKeyManagers()");
        return kmf.getKeyManagers();
    }

    @Override
    public TrustManager[] getTrustManagers() throws Exception {
        logger.debug("FIPSUtil: getTrustManagers()");
        return tmf.getTrustManagers();
    }

    @Override
    public void configureSessionContext(SSLSessionContext sslSessionContext) {
        logger.debug("FIPSUtil.configureSessionContext(...)");
        // don't do anything.
    }

    @Override
    public final SSLContext createSSLContext(List<String> negotiableProtocols) throws Exception {
        SSLContext sslContext = createSSLContextInternal(negotiableProtocols);
        sslContext.init(getKeyManagers(), getTrustManagers(), null);

        SSLSessionContext sessionContext = sslContext.getServerSessionContext();
        if (sessionContext != null) {
            configureSessionContext(sessionContext);
        }

        return sslContext;
    }

    protected SSLContext createSSLContextInternal(List<String> negotiableProtocols) throws Exception {
        logger.debug("FIPSUtil createSSLContextInternal(...) keyAlias=" + keyAlias);
        return new FIPSContext(keyAlias, ctx);
    }

    protected boolean isTls13RenegAuthAvailable() {
        logger.debug("FIPSUtil: isTls13RenegAuthAvailable()");
        return true;
    }

    protected Log getLog() {
        logger.debug("FIPSUtil: getLog()");
        return logger;
    }

    protected Set<String> getImplementedProtocols() {
        logger.debug("FIPSUtil: getImplementedProtocols()");

        // return new HashSet<String>(Arrays.asList(ctx.getSupportedSSLParameters().getProtocols()));

        // Shit's broke, yo!
        // https://bugzilla.redhat.com/show_bug.cgi?id=1760838
        return new HashSet<String>(Arrays.asList(new String[] {
            "SSL",
            "TLS",
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2",
        }));
    }

    protected Set<String> getImplementedCiphers() {
        logger.debug("FIPSUtil: getImplementedCiphers()");

        // return new HashSet<String>(Arrays.asList(ctx.getSupportedSSLParameters().getCipherSuites()));

        // Shit's broke, yo!
        // https://bugzilla.redhat.com/show_bug.cgi?id=1760838
        return new HashSet<String>(Arrays.asList(new String[] {
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        }));
    }
}
