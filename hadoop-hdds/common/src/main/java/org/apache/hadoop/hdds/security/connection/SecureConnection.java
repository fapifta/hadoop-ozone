/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.hadoop.hdds.security.connection;

import org.apache.hadoop.hdds.ratis.RatisHelper;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.ssl.KeyStoresFactory;
import org.apache.ratis.conf.Parameters;
import org.apache.ratis.grpc.GrpcTlsConfig;
import org.apache.ratis.thirdparty.io.grpc.netty.GrpcSslContexts;
import org.apache.ratis.thirdparty.io.grpc.netty.NettyChannelBuilder;
import org.apache.ratis.thirdparty.io.grpc.netty.NettyServerBuilder;
import org.apache.ratis.thirdparty.io.netty.handler.ssl.ClientAuth;
import org.apache.ratis.thirdparty.io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;

import javax.net.ssl.SSLException;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.apache.ratis.thirdparty.io.netty.handler.ssl.SslContextBuilder.forServer;

/**
 * TBD.
 */
class SecureConnection implements ConnectionConfigurator {

  private SecurityConfig config;
  private KeyStoresFactory serverKeyStores;
  private KeyStoresFactory clientKeyStores;
  private List<X509Certificate> trustedCerts;

  SecureConnection(
      SecurityConfig securityConfig,
      KeyStoresFactory serverKeyStores,
      KeyStoresFactory clientKeyStores) {
    this.config = securityConfig;
    this.serverKeyStores = serverKeyStores;
    this.clientKeyStores = clientKeyStores;
    trustedCerts = Arrays.asList(
        ((X509TrustManager) clientKeyStores.getTrustManagers()[0])
            .getAcceptedIssuers()
    );
  }

  @Override
  public void secureXceiverServerGrpcConditionally(
      NettyServerBuilder builder,
      Logger log
  ) {
    if (!config.isSecurityEnabled() || !config.isGrpcTlsEnabled()) {
      return;
    }
    try {
      SslContextBuilder context =
          GrpcSslContexts.configure(
              forServer(serverKeyStores.getKeyManagers()[0]),
              config.getGrpcSslProvider()
          );
      builder.sslContext(context.build());
    } catch (Exception ex) {
      log.error("Unable to setup TLS for secure datanode GRPC endpoint.", ex);
    }
  }

  @Override
  public void secureReplicationServerConditionally(NettyServerBuilder builder) {
    if (!config.isSecurityEnabled() || !config.isGrpcTlsEnabled()) {
      return;
    }
    try {
      SslContextBuilder sslContextBuilder =
          GrpcSslContexts.configure(
              forServer(serverKeyStores.getKeyManagers()[0]),
              config.getGrpcSslProvider()
          );

      sslContextBuilder.clientAuth(ClientAuth.REQUIRE);
      sslContextBuilder.trustManager(serverKeyStores.getTrustManagers()[0]);

      builder.sslContext(sslContextBuilder.build());
    } catch (IOException ex) {
      throw new IllegalArgumentException(
          "Unable to setup TLS for secure datanode replication GRPC endpoint.",
          ex
      );
    }
  }

  @Override
  public Parameters secureRaftConnectionParameters() {
    if (!config.isSecurityEnabled() || !config.isGrpcTlsEnabled()) {
      return null;
    }
    GrpcTlsConfig serverConfig = new GrpcTlsConfig(
        serverKeyStores.getKeyManagers()[0],
        serverKeyStores.getTrustManagers()[0], true);
    GrpcTlsConfig clientConfig = new GrpcTlsConfig(
        serverKeyStores.getKeyManagers()[0],
        serverKeyStores.getTrustManagers()[0], false);
    return RatisHelper.setServerTlsConf(serverConfig, clientConfig);
  }

  @Override
  public List<X509Certificate> trustedCerts() {
    return trustedCerts;
  }

  @Override
  public GrpcTlsConfig secureClientGrpcTlsConfigWithMTLS() {
    if (!config.isSecurityEnabled() || !config.isGrpcTlsEnabled()) {
      return null;
    }
    return new GrpcTlsConfig(
        clientKeyStores.getKeyManagers()[0],
        clientKeyStores.getTrustManagers()[0],
        true
    );
  }









  public void configureClientWithMTLS(NettyChannelBuilder builder)
      throws SSLException {
    if (!tlsEnabled()) {
      return;
    }
    configureGenericSSLProperties(builder);
    SslContextBuilder sslContextBuilder = GrpcSslContexts.forClient();
    sslContextBuilder.clientAuth(ClientAuth.REQUIRE);
    sslContextBuilder.trustManager(clientKeyStores.getTrustManagers()[0]);
    sslContextBuilder.keyManager(clientKeyStores.getKeyManagers()[0]);
    builder.sslContext(sslContextBuilder.build());
  }

  public void configureSSLClientIfNeeded(NettyChannelBuilder builder)
      throws SSLException {
    if (!tlsEnabled()) {
      return;
    }
    configureGenericSSLProperties(builder);
    SslContextBuilder sslContextBuilder = GrpcSslContexts.forClient();
    sslContextBuilder.trustManager(clientKeyStores.getTrustManagers()[0]);
    builder.sslContext(sslContextBuilder.build());
  }

  public GrpcTlsConfig clientTlsConfig() {
    if (!tlsEnabled()) {
      return null;
    }
    return new GrpcTlsConfig(
        clientKeyStores.getKeyManagers()[0],
        serverKeyStores.getTrustManagers()[0],
        true);
  }

  protected boolean tlsEnabled() {
    return config.isSecurityEnabled() && config.isGrpcTlsEnabled();
  }

  protected SecurityConfig config() {
    return config;
  }

  private void configureGenericSSLProperties(NettyChannelBuilder builder) {
    builder.useTransportSecurity();
    if (config.useTestCert()) {
      builder.overrideAuthority("localhost");
    }
  }
}
