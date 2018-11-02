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
 * Copyright (C) 2007 Red Hat, Inc.
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

public class JSSSocketFactory extends
        javax.net.ssl.SSLServerSocketFactory {

    public static Logger logger = LoggerFactory.getLogger(JSSUtil.class);

    TomcatJSS tomcatjss = TomcatJSS.getInstance();

    private Properties config;

    public JSSSocketFactory(Properties config) {
        this.config = config;
    }

    String getProperty(String tag) {
        // if not available, check <catalina.base>/conf/tomcatjss.conf
        return config.getProperty(tag);
    }

    String getProperty(String tag, String defaultValue) {
        String value = config.getProperty(tag);
        if (value == null) {
            return defaultValue;
        }
        return value;
    }

    public Socket acceptSocket(ServerSocket socket) throws IOException {
        SSLSocket asock = null;
        try {
            asock = (SSLSocket) socket.accept();
            asock.addSocketListener(tomcatjss);

            if (tomcatjss.getRequireClientAuth() || tomcatjss.getWantClientAuth()) {
                asock.requestClientAuth(true);
                if (tomcatjss.getRequireClientAuth()) {
                    asock.requireClientAuth(SSLSocket.SSL_REQUIRE_ALWAYS);
                } else {
                    asock.requireClientAuth(SSLSocket.SSL_REQUIRE_NEVER);
                }
            }
        } catch (Exception e) {
            throw new SocketException("SSL handshake error " + e.toString());
        }

        return asock;
    }

    public void handshake(Socket sock) throws IOException {
        // ((SSLSocket)sock).forceHandshake();
    }

    public ServerSocket createServerSocket(int port) throws IOException {
        return createServerSocket(port, SSLServerSocket.DEFAULT_BACKLOG, null);
    }

    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return createServerSocket(port, backlog, null);
    }

    public ServerSocket createServerSocket(int port, int backlog,
            InetAddress ifAddress) throws IOException {
        return createServerSocket(port, backlog, ifAddress, true);
    }

    public ServerSocket createServerSocket(int port, int backlog,
            InetAddress ifAddress, boolean reuseAddr) throws IOException {

        SSLServerSocket socket = null;
        socket = new SSLServerSocket(port, backlog, ifAddress, null, reuseAddr);
        initializeSocket(socket);
        return socket;
    }

    private void initializeSocket(SSLServerSocket s) {
        try {
            /*
             * Timeout's should not be enabled by default. Upper layers will
             * call setSoTimeout() as needed. Zero means disable.
             */
            s.setSoTimeout(0);
            if (tomcatjss.getRequireClientAuth() || tomcatjss.getWantClientAuth()) {
                s.requestClientAuth(true);
                if (tomcatjss.getRequireClientAuth()) {
                    s.requireClientAuth(SSLSocket.SSL_REQUIRE_ALWAYS);
                } else {
                    s.requireClientAuth(SSLSocket.SSL_REQUIRE_NEVER);
                }
            }
            String serverCertNick = tomcatjss.getServerCertNick();
            s.setServerCertNickname(serverCertNick);
        } catch (Exception e) {
        }
    }

    public String[] getDefaultCipherSuites() {
        return null;
    }

    public String[] getSupportedCipherSuites() {
        return null;
    }
}
