package com.jcraft.jsch;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;

/**
 * Representation of an SSH host certificate.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-sshm-cert-01.html">SSH Certificate
 *      Format</a>
 */
public class HostCertificate {

  private final String host;
  private final OpenSshCertificate cert;

  HostCertificate(String host, OpenSshCertificate cert) {
    this.host = host;
    this.cert = cert;
  }

  public String getHost() {
    return host;
  }

  public String getKeyType() {
    return cert.getKeyType();
  }

  public String getPublicKey() {
    byte[] key = cert.getCertificatePublicKey();
    return key == null ? null : Util.byte2str(Util.toBase64(key, 0, key.length, true));
  }

  public String getPublicKeyFingerPrint(JSch jsch) {
    byte[] key = cert.getCertificatePublicKey();
    return key == null ? null : _fingerPrint(jsch, key, "getPublicKeyFingerPrint");
  }

  public long getSerialNumber() {
    return cert.getSerial();
  }

  public int getCertificateRole() {
    return cert.getType();
  }

  public String getIdentifier() {
    return cert.getId();
  }

  public Collection<String> getPrincipals() {
    return cert.getPrincipals();
  }

  public long getValidAfter() {
    return cert.getValidAfter();
  }

  public long getValidBefore() {
    return cert.getValidBefore();
  }

  public Map<String, String> getCriticalOptions() {
    return cert.getCriticalOptions();
  }

  public Map<String, String> getExtensions() {
    return cert.getExtensions();
  }

  public String getSignatureKey() {
    byte[] key = cert.getSignatureKey();
    return key == null ? null : Util.byte2str(Util.toBase64(key, 0, key.length, true));
  }

  public String getSignatureKeyType() {
    byte[] key = cert.getSignatureKey();
    if (key == null) {
      return null;
    }
    Buffer buf = new Buffer(key);
    return Util.byte2str(buf.getString());
  }

  public String getSignatureKeyFingerPrint(JSch jsch) {
    byte[] key = cert.getSignatureKey();
    return key == null ? null : _fingerPrint(jsch, key, "getSignatureKeyFingerPrint");
  }

  public String getSignatureAlgorithm() {
    byte[] sig = cert.getSignature();
    if (sig == null) {
      return null;
    }
    Buffer buf = new Buffer(sig);
    return Util.byte2str(buf.getString());
  }

  private static String _fingerPrint(JSch jsch, byte[] key, String method) {
    HASH hash = null;
    try {
      String _c = JSch.getConfig("FingerprintHash").toLowerCase(Locale.ROOT);
      Class<? extends HASH> c = Class.forName(JSch.getConfig(_c)).asSubclass(HASH.class);
      hash = c.getDeclaredConstructor().newInstance();
    } catch (Exception e) {
      if (jsch.getInstanceLogger().isEnabled(Logger.ERROR)) {
        jsch.getInstanceLogger().log(Logger.ERROR, method + ": " + e.getMessage(), e);
      }
    }
    return Util.getFingerPrint(hash, key, true, false);
  }
}
