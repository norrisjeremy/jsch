/*
 * Copyright (c) 2015-2018 ymnk, JCraft,Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided with
 * the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL JCRAFT, INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jcraft.jsch.jce;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KEM;

abstract class MLKEM implements com.jcraft.jsch.KEM {
  protected NamedParameterSpec params;
  protected byte[] algorithmIdentifier;
  protected int publicKeyLen;
  KEM.Decapsulator decapsulator;
  byte[] publicKey;

  @Override
  public void init() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
    kpg.initialize(params);
    KeyPair kp = kpg.generateKeyPair();
    KEM kem = KEM.getInstance("ML-KEM");
    decapsulator = kem.newDecapsulator(kp.getPrivate());
    publicKey = com.jcraft.jsch.KeyPair.extractX509SubjectPublicKeyInfo(kp.getPublic().getEncoded(),
        algorithmIdentifier, publicKeyLen);
  }

  @Override
  public byte[] getPublicKey() throws Exception {
    return publicKey;
  }

  @Override
  public byte[] decapsulate(byte[] encapsulation) throws Exception {
    return decapsulator.decapsulate(encapsulation).getEncoded();
  }
}
