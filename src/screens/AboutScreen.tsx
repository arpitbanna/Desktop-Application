import React from 'react';
import { View, Text, StyleSheet, ScrollView } from 'react-native';
import { colors } from '../theme/colors';
import { CyberCard } from '../components/CyberCard';
import { SecurityBadge } from '../components/SecurityBadge';

export const AboutScreen: React.FC = () => {
  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Intro Card */}
      <CyberCard
        title="ABOUT TRUSTROOT MOBILE"
        subtitle="UIDAI Hardware-Enabled Root of Trust Architecture"
        badge={<SecurityBadge label="OFFLINE PKI" variant="custom" />}
      >
        <Text style={styles.paragraph}>
          TrustRoot Mobile is a security prototype demonstrating how Android and iOS mobile devices establish a hardware-backed cryptographic identity and protect sensitive image or biometric data locally without requiring any cloud or backend service.
        </Text>
      </CyberCard>

      {/* Explanatory Cards */}
      <CyberCard title="1. WHAT IS A HARDWARE-BACKED KEY?" subtitle="Physical security coprocessor isolation">
        <Text style={styles.paragraph}>
          A hardware-backed key is generated and stored inside a dedicated cryptographic processor (such as Android StrongBox HSM, ARM TrustZone TEE, or Apple Secure Enclave).
        </Text>
        <Text style={styles.paragraph}>
          Private key operations (such as digital signing) execute inside this isolated environment. The host operating system kernel never has direct access to the private key bytes.
        </Text>
      </CyberCard>

      <CyberCard title="2. WHAT DOES NON-EXPORTABLE MEAN?" subtitle="Silico-enforced key containment">
        <Text style={styles.paragraph}>
          Non-exportable means the private key material cannot be read out of secure hardware. There is no API or memory address to dump the raw key bytes.
        </Text>
        <Text style={styles.paragraph}>
          Even if an attacker gains root privileges on the device or dumps the application process memory, they cannot extract the private key.
        </Text>
      </CyberCard>

      <CyberCard title="3. HOW HYBRID ENCRYPTION WORKS" subtitle="Symmetric bulk encryption + Asymmetric key wrapping">
        <Text style={styles.paragraph}>
          Directly encrypting large image files with RSA is impossible due to RSA message length limits.
        </Text>
        <Text style={styles.paragraph}>
          Instead, TrustRoot Mobile generates a fresh, ephemeral 256-bit AES key and unique 96-bit nonce for each payload, encrypts the image using AES-256-GCM, and then wraps (encrypts) the small AES key using the intended recipient's RSA public key (RSA-OAEP with SHA-256).
        </Text>
      </CyberCard>

      <CyberCard title="4. WHAT CAN BE PROVEN LOCALLY" subtitle="Zero-network local guarantees">
        <Text style={styles.bullet}>• Authenticity of the package: AES-GCM 128-bit tag confirms ciphertext has not been tampered.</Text>
        <Text style={styles.bullet}>• Device origin: Hardware digital signature confirms the package originated from this device.</Text>
        <Text style={styles.bullet}>• Key validity against local policy: Expired or locally revoked keys are rejected immediately.</Text>
        <Text style={styles.bullet}>• Authorized test recovery: The test recipient can decrypt and recover exact original bytes.</Text>
      </CyberCard>

      <CyberCard title="5. WHAT REQUIRES EXTERNAL VERIFICATION" subtitle="Global trust boundaries">
        <Text style={styles.bullet}>• Global Revocation: Real-time discovery of certificates revoked elsewhere requires an online CRL/OCSP sync.</Text>
        <Text style={styles.bullet}>• Hardware Root Attestation: Verifying that an Android attestation chain links to Google's Root CA requires public root trust store verification.</Text>
        <Text style={styles.bullet}>• Production UIDAI Decryption: Final decryption occurs inside UIDAI's Central Identity Data Repository (CIDR).</Text>
      </CyberCard>

      {/* Platform Limitations Note */}
      <CyberCard
        title="6. HONEST PLATFORM LIMITATIONS"
        subtitle="Hardware realities on Android and iOS"
        variant="highlight"
      >
        <Text style={styles.paragraph}>
          <Text style={styles.bold}>Android Keystore:</Text> Supports StrongBox HSM (discrete chip) or TEE (TrustZone). Key attestation certificates are provided on supported devices.
        </Text>
        <Text style={styles.paragraph}>
          <Text style={styles.bold}>Apple Secure Enclave:</Text> Strictly supports elliptic curve NIST P-256 (secp256r1) signing. The Secure Enclave does NOT support RSA operations. TrustRoot honestly generates the device identity key inside the Secure Enclave, while RSA-OAEP wrapping executes via Apple's platform Security framework.
        </Text>
      </CyberCard>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  paragraph: {
    fontSize: 13,
    color: colors.textSecondary,
    lineHeight: 18,
    marginBottom: 8
  },
  bullet: {
    fontSize: 12,
    color: colors.textSecondary,
    lineHeight: 18,
    marginBottom: 4
  },
  bold: {
    color: colors.textPrimary,
    fontWeight: '700'
  }
});
