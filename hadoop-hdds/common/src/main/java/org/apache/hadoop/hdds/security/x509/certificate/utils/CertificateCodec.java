/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.hadoop.hdds.security.x509.certificate.utils;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import static org.apache.hadoop.hdds.security.exception.SCMSecurityException.ErrorCode.PEM_ENCODE_FAILED;

/**
 * A class used to read and write X.509 certificates  PEM encoded Streams.
 */
public final class CertificateCodec {

  public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

  private static final Logger LOG =
      LoggerFactory.getLogger(CertificateCodec.class);
  private static CertificateCodec instance = new CertificateCodec();

  public static CertificateCodec get() {
    if (instance != null) {
      instance = new CertificateCodec();
    }
    return instance;
  }

  private CertificateCodec() {

  }

  /**
   * Get a valid pem encoded string for the certification path.
   */
  public String encode(CertPath certPath) throws IOException {
    List<? extends Certificate> certsInPath = certPath.getCertificates();
    ArrayList<String> pemEncodedList = new ArrayList<>(certsInPath.size());
    for (Certificate cert : certsInPath) {
      pemEncodedList.add(encode((X509Certificate) cert));
    }
    return StringUtils.join(pemEncodedList, "\n");
  }

  /**
   * Returns the Certificate as a PEM encoded String.
   *
   * @param certificate - X.509 Certificate.
   * @return PEM Encoded Certificate String.
   * @throws SCMSecurityException - On failure to create a PEM String.
   */
  public String encode(X509Certificate certificate) throws IOException {
    try {
      return writePEMEncoded(certificate, new StringWriter()).toString();
    } catch (IOException e) {
      LOG.error("Error in encoding certificate." + certificate
          .getSubjectDN().toString(), e);
      throw new SCMSecurityException("PEM Encoding failed for certificate." +
          certificate.getSubjectDN().toString(), e, PEM_ENCODE_FAILED);
    }
  }

  public CertPath decode(InputStream inputStream) throws IOException {
    try {
      return CertificateFactory.getInstance("X.509", "BC").generateCertPath(inputStream, "PEM");
    } catch (CertificateException e) {
      throw new IOException(e);
    } catch (NoSuchProviderException e) {
      throw new RuntimeException("Certificate factory provider not loaded.", e);
    }
  }

  /**
   * Encode the given certificate in PEM
   * and then write it out to the given {@link Writer}.
   *
   * @param <W> The writer type.
   */
  private static <W extends Writer> W writePEMEncoded(X509Certificate certificate, W writer) throws IOException {
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(certificate);
    }
    return writer;
  }
}
