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

package org.apache.tomcat.util.net.jss;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Properties;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;

// Imports required to "implement" Tomcat 7 Interface
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SSLContext;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSContext implements
        org.apache.tomcat.util.net.SSLContext {

    public static Logger logger = LoggerFactory.getLogger(JSSUtil.class);

    TomcatJSS tomcatjss = TomcatJSS.getInstance();
    Properties config;

    List<String> protocols;

    public JSSContext(List<String> negotiableProtocols, Properties config) {
        protocols = negotiableProtocols;
        config = config;
    }


    public void init(javax.net.ssl.KeyManager[] kms,
                     javax.net.ssl.TrustManager[] tms,
                     java.security.SecureRandom sr)
            throws java.security.KeyManagementException {
    }


    public void destroy() {}

    public javax.net.ssl.SSLSessionContext getServerSessionContext() {
        return null;
    }

    public javax.net.ssl.SSLEngine createSSLEngine() {
        return null;
    }

    public javax.net.ssl.SSLServerSocketFactory getServerSocketFactory() {
        return new JSSSocketFactory(config);
    }

    public javax.net.ssl.SSLParameters getSupportedSSLParameters() {
        return null;
    }

    public java.security.cert.X509Certificate[] getCertificateChain(java.lang.String alias) {
        return null;
    }


    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}
