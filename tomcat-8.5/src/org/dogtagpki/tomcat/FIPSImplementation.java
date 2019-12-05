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

package org.dogtagpki.tomcat;

import javax.net.ssl.SSLSession;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLImplementation;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SSLUtil;

import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FIPSImplementation extends SSLImplementation {

    public static Logger logger = LoggerFactory.getLogger(FIPSUtil.class);

    public static KeyStore ks;
    public static KeyManagerFactory kmf;
    public static TrustManagerFactory tmf;

    public FIPSImplementation() {
        logger.info("FIPSImplementation: instance created");
    }

    @Override
    public SSLSupport getSSLSupport(SSLSession session) {
        logger.info("FIPSImplementation.getSSLSupport()");
        return null;
    }

    public void initializeKeyStore(SSLHostConfig cfg) {
        if (ks == null) {
            try {
                logger.info("FIPSImplementation.initializeKeyStore(): not initialized... ...trying to load");

                ks = KeyStore.getInstance("PKCS11");
                kmf = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
                tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");

                String catalinaBase = System.getProperty("catalina.base");
                String jssConf = catalinaBase + "/conf/nssdb.password";
                File configFile = new File(jssConf);

                if (configFile.exists()) {
                    List<String> lines = Files.readAllLines(configFile.toPath());
                    logger.info("FIPSImplementation.initializeKeyStore(): Using password from " + configFile.toString() + " [ ==" + lines.get(0) + " ]");
                    ks.load(null, lines.get(0).toCharArray());
                    kmf.init(ks, lines.get(0).toCharArray());
                } else if (cfg.getTruststorePassword() != null) {
                    logger.info("FIPSImplementation.initializeKeyStore(): Using password from config: " + cfg.getTruststorePassword());
                    ks.load(null, cfg.getTruststorePassword().toCharArray());
                    kmf.init(ks, cfg.getTruststorePassword().toCharArray());
                } else {
                    // Password must be supplied, so try the empty password.
                    logger.info("FIPSImplementation.initializeKeyStore(): Using null password");
                    ks.load(null, "".toCharArray());
                    kmf.init(ks, "".toCharArray());
                }

                tmf.init(ks);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }

    @Override
    public SSLUtil getSSLUtil(SSLHostConfigCertificate cert) {
        logger.info("FIPSImplementation: getSSLUtil() : " + CertToStr(cert));

        initializeKeyStore(cert.getSSLHostConfig());
        return new FIPSUtil(cert, kmf, tmf);
    }

    @Override
    public boolean isAlpnSupported() {
        // NSS supports ALPN
        return true;
    }

    private static String CertToStr(SSLHostConfigCertificate cert) {
        return "{ chainFile=" + cert.getCertificateChainFile() + " file=" + cert.getCertificateFile() + " keyAlias=" + cert.getCertificateKeyAlias() + " keyFile=" + cert.getCertificateKeyFile() + " password=" + cert.getCertificateKeyPassword() + " type=" + cert.getType().toString() + " }";
    }
}
