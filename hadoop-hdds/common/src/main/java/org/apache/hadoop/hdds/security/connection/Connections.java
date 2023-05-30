package org.apache.hadoop.hdds.security.connection;

import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.certificate.client.CertificateClient;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;

/**
 * TBD.
 */
public class Connections {

  private Connections() {
    // no instantiation
  }

  public static ConnectionConfigurator configurator(
      SecurityConfig securityConf,
      CertificateClient certClient
  ) throws CertificateException {
    if (securityConf != null &&
        securityConf.isSecurityEnabled() && securityConf.isGrpcTlsEnabled()) {
      return new SecureConnection(
          securityConf,
          certClient.getServerKeyStoresFactory(),
          certClient.getClientKeyStoresFactory());
    } else {
      return new PlainConnection();
    }
  }
}
